import { getAlertById } from "@/lib/db/alerts"
import { upsertEnrichment } from "@/lib/db/enrichments"
import { getLLMClient } from "./index"
import { getSetting } from "@/lib/db/settings"
import { extractIndicators } from "@/lib/indicators"
import { enrichAlertWithThreatIntel } from "@/lib/threat-intel/enrich"
import { updateAlertIncidentStatus, updateAlertSeverity, updateAlertVerdict } from "@/lib/db/alerts"
import type { AlertVerdict, Severity } from "@/lib/types"
import { systemLog } from "@/lib/system-log"

type AgentResult = {
  analysis: string
  aiScore?: number
  severity?: Severity
  iocType?: string
  recommendation?: string
  mitreTactic?: string
  mitreTechnique?: string
}

const AGENT_PROMPT = `You are a SOC analyst specialist.
Return ONLY valid JSON with:
{
  "analysis": "short technical paragraph",
  "aiScore": 0-100,
  "severity": "critical|high|medium|low|info",
  "iocType": "IP|Domain|Hash|URL|Email|Mixed|Unknown",
  "recommendation": "numbered incident-response actions",
  "mitreTactic": "MITRE tactic",
  "mitreTechnique": "MITRE technique id and name"
}`

function toNumberInRange(value: unknown, fallback: number): number {
  if (typeof value !== "number" || Number.isNaN(value)) return fallback
  if (value < 0) return 0
  if (value > 100) return 100
  return Math.round(value)
}

function parseAgentJson(raw: string): AgentResult {
  try {
    const jsonMatch = raw.match(/\{[\s\S]*\}/)
    const obj = JSON.parse(jsonMatch ? jsonMatch[0] : raw) as Record<string, unknown>
    const sevRaw = String(obj.severity || "").toLowerCase()
    const severity: Severity | undefined =
      sevRaw === "critical" || sevRaw === "high" || sevRaw === "medium" || sevRaw === "low" || sevRaw === "info"
        ? (sevRaw as Severity)
        : undefined
    return {
      analysis: String(obj.analysis || "").trim(),
      aiScore:
        typeof obj.aiScore === "number"
          ? obj.aiScore
          : typeof obj.confidence === "number"
            ? obj.confidence
            : undefined,
      severity,
      iocType: obj.iocType ? String(obj.iocType) : undefined,
      recommendation: obj.recommendation ? String(obj.recommendation) : undefined,
      mitreTactic: obj.mitreTactic ? String(obj.mitreTactic) : undefined,
      mitreTechnique: obj.mitreTechnique ? String(obj.mitreTechnique) : undefined,
    }
  } catch {
    return { analysis: raw.trim() || "No analysis returned." }
  }
}

function buildHeuristicFallback(input: {
  title: string
  severity: string
  source: string
  description: string
  indicators: ReturnType<typeof extractIndicators>
  threatIntel: string
}): AgentResult {
  const indicatorSummary = [
    input.indicators.ips.length ? `IPs: ${input.indicators.ips.join(", ")}` : "",
    input.indicators.urls.length ? `URLs: ${input.indicators.urls.join(", ")}` : "",
    input.indicators.domains.length ? `Domains: ${input.indicators.domains.join(", ")}` : "",
    input.indicators.hashes.length ? `Hashes: ${input.indicators.hashes.join(", ")}` : "",
  ]
    .filter(Boolean)
    .join(" | ")

  const baseScore =
    input.severity === "critical" ? 85 : input.severity === "high" ? 72 : input.severity === "medium" ? 58 : 42

  return {
    analysis: `Heuristic analysis (no LLM key configured): ${input.title} from ${input.source}. ${input.description}. ${indicatorSummary || "No indicators extracted."} Threat intel: ${input.threatIntel}`,
    aiScore: baseScore,
    severity:
      input.severity === "critical" || input.severity === "high" || input.severity === "medium" || input.severity === "low" || input.severity === "info"
        ? (input.severity as Severity)
        : "medium",
    iocType:
      input.indicators.urls.length > 0 || input.indicators.domains.length > 0 || input.indicators.ips.length > 0
        ? "Mixed"
        : "Unknown",
    recommendation:
      "1. Validate source host context and isolate if suspicious. 2. Block confirmed malicious indicators. 3. Hunt for related events in adjacent logs. 4. Escalate if repeated activity persists.",
  }
}

function computeHeuristicsScore(input: {
  severity: Severity
  indicators: ReturnType<typeof extractIndicators>
  hasThreatIntel: boolean
  hasYaraMatch: boolean
}): number {
  const severityBase: Record<Severity, number> = {
    critical: 92,
    high: 78,
    medium: 62,
    low: 42,
    info: 24,
  }

  const iocWeight =
    input.indicators.ips.length * 5 +
    input.indicators.urls.length * 7 +
    input.indicators.domains.length * 6 +
    input.indicators.hashes.length * 8 +
    input.indicators.filenames.length * 2

  let score = severityBase[input.severity] + Math.min(20, iocWeight)
  if (input.hasThreatIntel) score += 8
  if (input.hasYaraMatch) score += 10
  return Math.max(0, Math.min(100, Math.round(score)))
}

async function runAgent(client: Awaited<ReturnType<typeof getLLMClient>>, userPrompt: string): Promise<AgentResult> {
  const response = await client.chat([
    { role: "system", content: AGENT_PROMPT },
    { role: "user", content: userPrompt },
  ])
  return parseAgentJson(response.content)
}

const severityRank: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

function aggregateSeverity(candidates: Severity[], fallback: Severity): Severity {
  if (candidates.length === 0) return fallback
  const best = candidates.reduce((max, cur) => (severityRank[cur] > severityRank[max] ? cur : max), candidates[0])
  return best
}

export async function enrichAlertWithLLM(alertId: string): Promise<void> {
  systemLog("info", "llm", "Starting LLM enrichment", { alertId })
  await enrichAlertWithThreatIntel(alertId).catch(() => {
    // Threat intel enrichment is best-effort.
  })

  const alert = await getAlertById(alertId)
  if (!alert) throw new Error(`Alert ${alertId} not found`)

  const settings = await getSetting<{
    provider: "openai" | "anthropic" | "local" | "custom"
    model: string
    analysisAgents?: number
    autoStatusConfidenceThreshold?: number
    verdictMaliciousThreshold?: number
    verdictSuspiciousThreshold?: number
  }>("llm", {
    provider: "openai",
    model: "gpt-4.1-nano",
    analysisAgents: 3,
    autoStatusConfidenceThreshold: 90,
    verdictMaliciousThreshold: 80,
    verdictSuspiciousThreshold: 45,
  })

  const indicators = extractIndicators([alert.title, alert.description, alert.rawLog].join("\n"))
  const sharedContext = `
Alert ID: ${alert.id}
Timestamp: ${alert.timestamp}
Title: ${alert.title}
Severity: ${alert.severity}
Source: ${alert.source}
Source IP: ${alert.sourceIp}
Destination IP: ${alert.destIp}
MITRE Tactic: ${alert.mitreTactic}
MITRE Technique: ${alert.mitreTechnique}
YARA Match: ${alert.yaraMatch || "None"}
Description: ${alert.description}
Raw Log: ${alert.rawLog.slice(0, 1200)}
Indicators:
- IPs: ${indicators.ips.join(", ") || "None"}
- URLs: ${indicators.urls.join(", ") || "None"}
- Domains: ${indicators.domains.join(", ") || "None"}
- Hashes: ${indicators.hashes.join(", ") || "None"}
- Filenames: ${indicators.filenames.join(", ") || "None"}
Threat Intel Snapshot:
${alert.enrichment.threatIntel || "No threat intel snapshot available."}
`

  const agentCount = Math.max(1, Math.min(4, settings.analysisAgents || 3))
  const prompts = [
    `Role: Incident Triage Expert.
Goal: Explain what happened, probable attacker objective, and assign AI score.
${sharedContext}`,
    `Role: IOC and Detection Expert.
Goal: Validate IOC type quality, tune MITRE mapping, note likely false positives.
${sharedContext}`,
    `Role: Threat Intelligence Correlation Expert.
Goal: Correlate the event against threat-intel data and assess risk of active compromise.
${sharedContext}`,
    `Role: Incident Response Lead.
Goal: Produce concise prioritized containment and investigation steps.
${sharedContext}`,
  ].slice(0, agentCount)

  const heuristicFallback = buildHeuristicFallback({
    title: alert.title,
    severity: alert.severity,
    source: alert.source,
    description: alert.description,
    indicators,
    threatIntel: alert.enrichment.threatIntel || "No threat-intel data.",
  })

  const agentResults: AgentResult[] = []
  let aiSuccessCount = 0

  try {
    const client = await getLLMClient()
    for (const prompt of prompts) {
      try {
        const result = await runAgent(client, prompt)
        if (result.analysis) {
          agentResults.push(result)
          aiSuccessCount += 1
        }
      } catch (err) {
        systemLog("warn", "llm", "Agent call failed", { alertId, error: String(err) })
        // Keep partial AI results from other agents; don't fail the whole enrichment.
      }
    }
  } catch (err) {
    systemLog("error", "llm", "Failed to initialize LLM client", { alertId, error: String(err) })
    // Client initialization failed; use fallback below.
  }

  if (agentResults.length === 0) {
    agentResults.push(heuristicFallback)
  }

  const analyses = agentResults.map((a, i) => `Agent ${i + 1}: ${a.analysis}`).filter(Boolean)
  const aiScores = agentResults.map((r) => r.aiScore).filter((v): v is number => typeof v === "number")
  const avgAiScore = aiScores.length
    ? Math.round(aiScores.reduce((a, b) => a + b, 0) / aiScores.length)
    : aiSuccessCount > 0
      ? 65
      : alert.enrichment.aiScore || alert.enrichment.confidence || heuristicFallback.aiScore || 0

  const iocType =
    agentResults.map((r) => r.iocType).find((v) => !!v && v !== "Unknown") ||
    alert.enrichment.iocType ||
    "Unknown"

  const recommendation =
    agentResults
      .map((r) => r.recommendation)
      .find((v) => !!v) ||
    alert.enrichment.recommendation ||
    "1. Validate scope and isolate affected assets. 2. Block high-confidence indicators. 3. Continue threat hunting."

  const aiSeverities = agentResults
    .map((r) => r.severity)
    .filter((s): s is Severity => !!s)
  const recategorizedSeverity = aggregateSeverity(aiSeverities, alert.severity)
  const heuristicsScore = computeHeuristicsScore({
    severity: recategorizedSeverity,
    indicators,
    hasThreatIntel: Boolean(alert.enrichment.threatIntel?.trim()),
    hasYaraMatch: Boolean(alert.yaraMatch),
  })

  await upsertEnrichment(alertId, {
    aiAnalysis: analyses.join("\n\n"),
    iocType,
    recommendation,
    confidence: toNumberInRange(avgAiScore, alert.enrichment.aiScore || alert.enrichment.confidence || 0),
    aiScore: toNumberInRange(avgAiScore, alert.enrichment.aiScore || alert.enrichment.confidence || 0),
    heuristicsScore: toNumberInRange(heuristicsScore, alert.enrichment.heuristicsScore || 0),
    llmProvider: settings.provider,
    llmModel: settings.model || "gpt-4.1-nano",
  })

  const autoStatusThreshold = settings.autoStatusConfidenceThreshold ?? 90
  const maliciousThreshold = Math.max(1, Math.min(100, settings.verdictMaliciousThreshold ?? 80))
  const suspiciousThreshold = Math.max(1, Math.min(maliciousThreshold - 1, settings.verdictSuspiciousThreshold ?? 45))
  const verdict: AlertVerdict =
    avgAiScore >= maliciousThreshold ? "malicious" : avgAiScore >= suspiciousThreshold ? "suspicious" : "false_positive"
  await updateAlertVerdict(alertId, verdict)
  await updateAlertSeverity(alertId, recategorizedSeverity)

  if (alert.incidentStatus === "unassigned" && avgAiScore >= autoStatusThreshold) {
    await updateAlertIncidentStatus(alertId, "in_progress")
  }

  systemLog("info", "llm", "LLM enrichment completed", { alertId, avgAiScore, verdict })
}
