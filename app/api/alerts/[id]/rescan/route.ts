import { NextRequest } from "next/server"
import { getAlertById, updateAlertFields } from "@/lib/db/alerts"
import { classifyLog } from "@/lib/pipeline/classifier"
import { classifyWithSigma } from "@/lib/sigma"
import { scanLogMessage } from "@/lib/yara"
import { extractStructuredFields } from "@/lib/ingestion/structured-fields"
import { upsertEnrichment } from "@/lib/db/enrichments"
import { getSetting } from "@/lib/db/settings"
import { getThreatFeeds } from "@/lib/db/threat-feeds"
import type { Severity } from "@/lib/types"

function detectSeverity(message: string): Severity {
  const lower = message.toLowerCase()
  if (/critical|emergency|fatal|panic/.test(lower)) return "critical"
  if (/error|fail|denied|attack|alert|breach|exploit/.test(lower)) return "high"
  if (/warn|warning|suspicious|unusual|anomal/.test(lower)) return "medium"
  if (/notice|info|success|accept/.test(lower)) return "low"
  return "info"
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params
  const alert = await getAlertById(id)
  if (!alert) return new Response("Not found", { status: 404 })

  const encoder = new TextEncoder()
  const { signal } = request

  const stream = new ReadableStream({
    async start(controller) {
      const emit = (data: object) => {
        if (signal.aborted) return
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`))
        } catch {}
      }

      signal.addEventListener("abort", () => {
        try { controller.close() } catch {}
      })

      try {
        // Load settings in parallel
        const [llmSettings, sigmaSettings, yaraSettings, threatFeeds] = await Promise.all([
          getSetting<{ provider?: string; apiKey?: string; model?: string }>("llm", {}),
          getSetting<{ enabled?: boolean }>("sigma", {}),
          getSetting<{ enabled?: boolean }>("yara", {}),
          getThreatFeeds(),
        ])
        const llmConfigured = !!(llmSettings?.apiKey && llmSettings?.provider && llmSettings.provider !== "local")
        const sigmaEnabled = !!sigmaSettings?.enabled
        const yaraEnabled = !!yaraSettings?.enabled
        const activeThreatFeeds = threatFeeds.filter((f) => f.enabled).length

        // ── Step 1: Severity Detection ──
        emit({ step: "severity", status: "running", detail: "Detecting severity..." })
        const severity = detectSeverity(alert.rawLog)
        await updateAlertFields(id, { severity })
        emit({ step: "severity", status: "ok", detail: severity.charAt(0).toUpperCase() + severity.slice(1) })
        if (signal.aborted) return

        // ── Step 2: Sigma Rules ──
        let sigmaResult: Awaited<ReturnType<typeof classifyWithSigma>> | null = null
        if (sigmaEnabled) {
          emit({ step: "sigma", status: "running", detail: "Running Sigma rules..." })
          sigmaResult = await classifyWithSigma(alert.rawLog, alert.source, true).catch(() => null)
          await upsertEnrichment(id, { sigmaMatch: sigmaResult?.sigma || null })
          emit({
            step: "sigma",
            status: sigmaResult?.sigma ? "match" : "no_match",
            detail: sigmaResult?.sigma?.title || "No match",
          })
        } else {
          emit({ step: "sigma", status: "disabled", detail: "Disabled" })
        }
        if (signal.aborted) return

        // ── Step 3: Built-in Classifier ──
        emit({ step: "classifier", status: "running", detail: "Classifying..." })
        const builtinClassification = classifyLog(alert.rawLog, alert.source)
        const classification = sigmaResult?.classification || builtinClassification
        if (classification) {
          await updateAlertFields(id, {
            mitreTactic: classification.mitreTactic,
            mitreTechnique: classification.mitreTechnique,
          })
        }
        emit({
          step: "classifier",
          status: classification?.mitreTactic && classification.mitreTactic !== "Unknown" ? "match" : "no_match",
          detail: classification?.mitreTactic || "No match",
        })
        if (signal.aborted) return

        // ── Step 4: YARA Scan ──
        if (yaraEnabled) {
          emit({ step: "yara", status: "running", detail: "Scanning with YARA..." })
          let yaraMatch: string | null = null
          try { yaraMatch = await scanLogMessage(alert.rawLog) } catch {}
          await updateAlertFields(id, { yaraMatch })
          emit({ step: "yara", status: yaraMatch ? "match" : "no_match", detail: yaraMatch || "No match" })
        } else {
          emit({ step: "yara", status: "disabled", detail: "Disabled" })
        }
        if (signal.aborted) return

        // ── Step 5: Field Extraction ──
        emit({ step: "fields", status: "running", detail: "Extracting fields..." })
        const structured = extractStructuredFields(alert.rawLog, true)
        await upsertEnrichment(id, { parseConfidence: structured.confidence })
        emit({
          step: "fields",
          status: structured.confidence > 50 ? "ok" : "no_match",
          detail: `${Math.round(structured.confidence)}% confidence`,
        })
        if (signal.aborted) return

        // ── Step 6: Threat Intel ──
        if (activeThreatFeeds > 0) {
          emit({ step: "threatintel", status: "running", detail: "Looking up threat intel..." })
          try {
            const { enrichAlertWithThreatIntel } = await import("@/lib/threat-intel/enrich")
            await enrichAlertWithThreatIntel(id)
            emit({
              step: "threatintel",
              status: "ok",
              detail: `${activeThreatFeeds} feed${activeThreatFeeds > 1 ? "s" : ""} checked`,
            })
          } catch {
            emit({ step: "threatintel", status: "error", detail: "Failed" })
          }
        } else {
          emit({ step: "threatintel", status: "disabled", detail: "No feeds configured" })
        }
        if (signal.aborted) return

        // ── Step 7: AI Analysis ──
        if (llmConfigured) {
          emit({ step: "ai", status: "running", detail: "Running AI analysis..." })
          try {
            const { enrichAlertWithLLM } = await import("@/lib/llm/enrich")
            await enrichAlertWithLLM(id)
            const updated = await getAlertById(id)
            emit({ step: "ai", status: "ok", detail: `Score ${updated?.enrichment.aiScore ?? "?"}` })
            // ── Step 8: Heuristics (derived from AI) ──
            const hScore = updated?.enrichment.heuristicsScore ?? 0
            emit({ step: "heuristics", status: hScore > 0 ? "ok" : "no_match", detail: `Score ${hScore}` })
          } catch {
            emit({ step: "ai", status: "error", detail: "Failed" })
            emit({ step: "heuristics", status: "no_match", detail: "Score 0" })
          }
        } else {
          emit({ step: "ai", status: "disabled", detail: "Not configured" })
          const updated = await getAlertById(id)
          const hScore = updated?.enrichment.heuristicsScore ?? 0
          emit({ step: "heuristics", status: hScore > 0 ? "ok" : "no_match", detail: `Score ${hScore}` })
        }

        emit({ done: true })
      } catch (err) {
        emit({ error: String(err) })
      } finally {
        try { controller.close() } catch {}
      }
    },
  })

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      "Connection": "keep-alive",
      "X-Accel-Buffering": "no",
    },
  })
}
