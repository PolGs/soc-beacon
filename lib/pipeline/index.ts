import { createLog } from "@/lib/db/logs"
import { createAlert } from "@/lib/db/alerts"
import { classifyLog } from "./classifier"
import { scanLogMessage } from "@/lib/yara"
import { classifyWithSigma } from "@/lib/sigma"
import { upsertEnrichment } from "@/lib/db/enrichments"
import { systemLog } from "@/lib/system-log"
import { extractAndMapLogFields } from "./field-extraction"
import type { Severity } from "@/lib/types"

interface IngestLogInput {
  timestamp?: string
  source: string
  message: string
  severity?: Severity
  parsed?: boolean
}

function detectSeverity(message: string): Severity {
  const lower = message.toLowerCase()
  if (/critical|emergency|fatal|panic/.test(lower)) return "critical"
  if (/error|fail|denied|attack|alert|breach|exploit/.test(lower)) return "high"
  if (/warn|warning|suspicious|unusual|anomal/.test(lower)) return "medium"
  if (/notice|info|success|accept/.test(lower)) return "low"
  return "info"
}

export async function ingestLog(input: IngestLogInput): Promise<{ logId: string; alertId?: string }> {
  // Step 1: Extract structured fields early (AI + heuristic), then map normalized columns.
  const extracted = await extractAndMapLogFields(input.message, input.parsed, input.source)
  const normalizedSource = extracted.mapped.source || input.source
  const sourceIp = extracted.mapped.sourceIp || "0.0.0.0"
  const destIp = extracted.mapped.destIp || "0.0.0.0"

  const baseSeverity = input.severity || detectSeverity(input.message)
  const timestamp = input.timestamp || new Date().toISOString()

  // Detect/classify first so missing severity can be upgraded from detection.
  const sigmaResult = await classifyWithSigma(input.message, normalizedSource, input.parsed).catch((err) => {
    systemLog("error", "sigma", "Sigma evaluation failed", { error: String(err) })
    return null
  })
  const builtinClassification = classifyLog(input.message, normalizedSource)
  const classification = sigmaResult?.classification || builtinClassification
  const effectiveSeverity = classification?.severity || baseSeverity

  // Create log entry
  const logId = await createLog({
    timestamp,
    source: normalizedSource,
    message: input.message,
    severity: effectiveSeverity,
    parsed: input.parsed ?? true,
  })

  // YARA scan
  let yaraMatch: string | null = null
  try {
    yaraMatch = await scanLogMessage(input.message)
  } catch {
    // YARA scan failed, continue without it
  }

  // Always create an alert for every accepted log entry.
  const alertData = {
    timestamp,
    source: normalizedSource,
    sourceIp,
    destIp,
    severity: effectiveSeverity,
    title: classification?.title || `${effectiveSeverity.toUpperCase()} severity event from ${input.source}`,
    description: classification?.description || input.message.slice(0, 200),
    yaraMatch,
    mitreTactic: classification?.mitreTactic || "Unknown",
    mitreTechnique: classification?.mitreTechnique || "Unknown",
    incidentStatus: "unassigned" as const,
    verdict: "suspicious" as const,
    rawLog: input.message,
    logId,
  }

  const alertId = await createAlert(alertData)
  if (sigmaResult?.sigma) {
    systemLog("info", "sigma", "Sigma rule matched", {
      alertId,
      title: sigmaResult.sigma.title,
      ruleId: sigmaResult.sigma.ruleId,
    })
  }

  await upsertEnrichment(alertId, {
    parseConfidence: extracted.confidence,
    extractedFields: extracted.fields,
    fieldConfidence: extracted.fieldConfidence as Record<string, number>,
    sigmaMatch: sigmaResult?.sigma,
  })

  // Always run threat intel enrichment in background.
  try {
    const { enrichAlertWithThreatIntel } = await import("@/lib/threat-intel/enrich")
    enrichAlertWithThreatIntel(alertId).catch(() => {
      // Async enrichment, don't block ingestion
    })
  } catch {
    systemLog("warn", "threat-intel", "Threat intel module unavailable", { alertId })
    // Threat intel module unavailable, skip
  }

  // Always run AI enrichment (uses LLM if configured, heuristic fallback otherwise).
  try {
    const { enrichAlertWithLLM } = await import("@/lib/llm/enrich")
    enrichAlertWithLLM(alertId).catch(() => {
      // Async enrichment, don't block
    })
  } catch {
    systemLog("warn", "llm", "LLM module unavailable", { alertId })
    // LLM module unavailable, skip
  }

  return { logId, alertId }
}

export async function ingestLogsBatch(
  logs: IngestLogInput[]
): Promise<{ logCount: number; alertCount: number }> {
  let alertCount = 0

  for (const log of logs) {
    const result = await ingestLog(log)
    if (result.alertId) alertCount++
  }

  return { logCount: logs.length, alertCount }
}
