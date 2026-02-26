import { NextRequest } from "next/server"
import { getAlertById, updateAlertFields } from "@/lib/db/alerts"
import { classifyLog } from "@/lib/pipeline/classifier"
import { extractAndMapLogFields } from "@/lib/pipeline/field-extraction"
import { classifyWithSigma } from "@/lib/sigma"
import { scanLogMessage } from "@/lib/yara"
import { upsertEnrichment } from "@/lib/db/enrichments"
import { getSetting } from "@/lib/db/settings"
import { getThreatFeeds } from "@/lib/db/threat-feeds"
import type { Severity } from "@/lib/types"
import { getSession } from "@/lib/auth"
import { validateApiKeyWithRateLimit } from "@/lib/security/api-auth"

async function validateAccess(request: NextRequest): Promise<{ ok: boolean; status: number; error: string }> {
  const session = await getSession()
  if (session) return { ok: true, status: 200, error: "" }
  return validateApiKeyWithRateLimit(request, "alerts:rescan", 30, 60_000)
}

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
  const auth = await validateAccess(request)
  if (!auth.ok) return new Response(auth.error, { status: auth.status })

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

        // Step 1: Field extraction and mapping
        emit({ step: "fields", status: "running", detail: "Extracting and mapping fields..." })
        const extracted = await extractAndMapLogFields(alert.rawLog, true, alert.source)
        await updateAlertFields(id, {
          source: extracted.mapped.source || alert.source,
          sourceIp: extracted.mapped.sourceIp || alert.sourceIp,
          destIp: extracted.mapped.destIp || alert.destIp,
        })
        await upsertEnrichment(id, {
          parseConfidence: extracted.confidence,
          extractedFields: extracted.fields,
          fieldConfidence: extracted.fieldConfidence as Record<string, number>,
        })
        emit({
          step: "fields",
          status: extracted.confidence > 50 ? "ok" : "no_match",
          detail: `${Math.round(extracted.confidence)}% confidence`,
        })
        if (signal.aborted) return

        // Step 2: Severity detection
        emit({ step: "severity", status: "running", detail: "Detecting severity..." })
        const severity = detectSeverity(alert.rawLog)
        await updateAlertFields(id, { severity })
        emit({ step: "severity", status: "ok", detail: severity.charAt(0).toUpperCase() + severity.slice(1) })
        if (signal.aborted) return

        // Step 3: Sigma rules
        let sigmaResult: Awaited<ReturnType<typeof classifyWithSigma>> | null = null
        if (sigmaEnabled) {
          emit({ step: "sigma", status: "running", detail: "Running Sigma rules..." })
          sigmaResult = await classifyWithSigma(alert.rawLog, extracted.mapped.source || alert.source, true).catch(() => null)
          await upsertEnrichment(id, { sigmaMatch: sigmaResult?.sigma || null })
          emit({
            step: "sigma",
            status: "ok",
            detail: sigmaResult?.sigma?.title ? `Executed · matched: ${sigmaResult.sigma.title}` : "Executed · no match",
          })
        } else {
          emit({ step: "sigma", status: "disabled", detail: "Disabled" })
        }
        if (signal.aborted) return

        // Step 4: Built-in classifier
        emit({ step: "classifier", status: "running", detail: "Classifying..." })
        const builtinClassification = classifyLog(alert.rawLog, extracted.mapped.source || alert.source)
        const classification = sigmaResult?.classification || builtinClassification
        if (classification) {
          await updateAlertFields(id, {
            mitreTactic: classification.mitreTactic,
            mitreTechnique: classification.mitreTechnique,
          })
        }
        emit({
          step: "classifier",
          status: "ok",
          detail:
            classification?.mitreTactic && classification.mitreTactic !== "Unknown"
              ? `Executed · mapped: ${classification.mitreTactic}`
              : "Executed · no mapping",
        })
        if (signal.aborted) return

        // Step 5: YARA scan
        if (yaraEnabled) {
          emit({ step: "yara", status: "running", detail: "Scanning with YARA..." })
          let yaraMatch: string | null = null
          try { yaraMatch = await scanLogMessage(alert.rawLog) } catch {}
          await updateAlertFields(id, { yaraMatch })
          emit({
            step: "yara",
            status: "ok",
            detail: yaraMatch ? `Executed · matched: ${yaraMatch}` : "Executed · no match",
          })
        } else {
          emit({ step: "yara", status: "disabled", detail: "Disabled" })
        }
        if (signal.aborted) return

        // Step 6: Threat intel
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

        // Step 7: AI analysis
        if (llmConfigured) {
          emit({ step: "ai", status: "running", detail: "Running AI analysis..." })
          try {
            const { enrichAlertWithLLM } = await import("@/lib/llm/enrich")
            await enrichAlertWithLLM(id)
            const updated = await getAlertById(id)
            emit({ step: "ai", status: "ok", detail: `Score ${updated?.enrichment.aiScore ?? "?"}` })
            // Step 8: Heuristics (derived from AI)
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
