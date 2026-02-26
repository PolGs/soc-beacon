import { getAlertById } from "@/lib/db/alerts"
import { upsertEnrichment } from "@/lib/db/enrichments"
import { getLLMClient } from "./index"
import { getSetting } from "@/lib/db/settings"
import { extractIndicators } from "@/lib/indicators"
import { enrichAlertWithThreatIntel } from "@/lib/threat-intel/enrich"
import { updateAlertIncidentStatus, updateAlertSeverity, updateAlertVerdict } from "@/lib/db/alerts"
import type { AlertVerdict, LLMAgentConfig, Severity } from "@/lib/types"
import { systemLog } from "@/lib/system-log"
import { formatHistoricalCasesForPrompt, retrieveHistoricalCasesForAlert, upsertAlertCaseToQdrant } from "@/lib/rag/qdrant"

type AgentResult = {
  analysis: string
  aiScore?: number
  severity?: Severity
  iocType?: string
  recommendation?: string
  mitreTactic?: string
  mitreTechnique?: string
}

type SourceThresholdPolicy = {
  maliciousThreshold?: number
  suspiciousThreshold?: number
  fpAutoResolveThreshold?: number
  minAutoResolveEvidence?: number
}

const AGENT_OUTPUT_SCHEMA_PROMPT = `You are a SOC analyst specialist.
Return ONLY valid JSON with:
{
  "analysis": "short technical paragraph",
  "aiScore": 0-100,
  "severity": "critical|high|medium|low|info",
  "iocType": "IP|Domain|Hash|URL|Email|Mixed|Unknown",
  "recommendation": "numbered incident-response actions",
  "mitreTactic": "MITRE tactic",
  "mitreTechnique": "MITRE technique id and name"
}

SCORING RUBRIC — aiScore represents malicious confidence based on the activity described in the raw log. Score the BEHAVIOUR, not the presence of external IOC hits:
95-100: Confirmed destructive/critical attack in progress — ransomware encrypting files, active data exfiltration confirmed, destructive wiper, confirmed C2 with data theft
85-94: Near-certain malicious activity — ransomware indicators (mass rename/encrypt + ransom note), credential dumping (mimikatz/lsass), active C2 beacon, lateral movement confirmed
70-84: High confidence threat — malicious macro/script execution, suspicious process spawning shells, known bad tool names (psexec abuse, cobalt strike), privilege escalation attempts
45-69: Suspicious, unconfirmed — anomalous behaviour without clear malicious intent, policy violations, single weak indicator, possible false positive
20-44: Low threat — minor anomalies, misconfigurations, unusual but likely benign
0-19: Almost certainly benign — expected system behaviour, known-good processes, noise

Calibration examples (score the log content, not missing external evidence):
- "3420 files renamed .lockbit + ransom note + bitcoin" → 97
- "mimikatz detected / lsass dump" → 93
- "AutoOpen() macro + WScript.Shell in email attachment" → 82
- "psexec lateral movement to 10 hosts" → 88
- "suspicious PowerShell -encodedcommand" → 74
- "failed logins from unknown country" → 38
- "port scan detected" → 48
- "normal auth from known IP" → 12

IMPORTANT: Absence of threat intel hits or external IP reputation data does NOT lower the score. Score what the log says happened.`

const DEFAULT_AGENTS: LLMAgentConfig[] = [
  {
    id: "triage",
    name: "Incident Triage Expert",
    description: "Scores risk and explains likely attacker objective.",
    enabled: true,
    model: "gpt-4.1-nano",
    prompt: "Explain what happened, probable attacker objective, and assign AI score.",
    maxTokens: 700,
    temperature: 0.1,
  },
  {
    id: "ioc_detection",
    name: "IOC and Detection Expert",
    description: "Validates indicators and detection quality, highlights likely false positives.",
    enabled: true,
    model: "gpt-4.1-nano",
    prompt: "Validate IOC type quality, tune MITRE mapping, and note likely false positives.",
    maxTokens: 700,
    temperature: 0.1,
  },
  {
    id: "threat_intel",
    name: "Threat Intelligence Correlation Expert",
    description: "Correlates event context with threat intel history and active compromise risk.",
    enabled: true,
    model: "gpt-4.1-nano",
    prompt: "Correlate event against threat intel and assess probability of active compromise.",
    maxTokens: 700,
    temperature: 0.1,
  },
  {
    id: "response",
    name: "Incident Response Lead",
    description: "Creates prioritized containment and investigation actions.",
    enabled: true,
    model: "gpt-4.1-nano",
    prompt: "Produce concise prioritized containment and investigation steps.",
    maxTokens: 700,
    temperature: 0.1,
  },
  {
    id: "summary_header",
    name: "Alert Header Summary Agent",
    description: "Generates a strict max-30-word alert summary for header display.",
    enabled: true,
    model: "gpt-4.1-nano",
    prompt: "Summarize this alert in one sentence, maximum 30 words, technical and actionable, no markdown.",
    maxTokens: 120,
    temperature: 0.1,
  },
]

function normalizeAgentConfigs(
  agents: LLMAgentConfig[] | undefined,
  defaults: { model: string; maxTokens: number; temperature: number }
): LLMAgentConfig[] {
  const raw = Array.isArray(agents) && agents.length > 0 ? agents : DEFAULT_AGENTS
  const normalized = raw
    .filter((a) => !!a && typeof a === "object")
    .map((a, idx) => ({
      id: (a.id || `agent_${idx + 1}`).toString(),
      name: (a.name || `Agent ${idx + 1}`).toString(),
      description: (a.description || "").toString(),
      enabled: a.enabled !== false,
      model: (a.model || defaults.model || "gpt-4.1-nano").toString(),
      prompt: (a.prompt || "").toString().trim(),
      maxTokens: typeof a.maxTokens === "number" ? a.maxTokens : defaults.maxTokens,
      temperature: typeof a.temperature === "number" ? a.temperature : defaults.temperature,
    }))
    .filter((a) => a.prompt.length > 0)

  const existingIds = new Set(normalized.map((a) => a.id))
  for (const base of DEFAULT_AGENTS) {
    if (existingIds.has(base.id)) continue
    normalized.push({
      ...base,
      model: defaults.model || base.model,
      maxTokens: defaults.maxTokens || base.maxTokens,
      temperature: defaults.temperature || base.temperature,
    })
  }
  return normalized
}

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

async function runAgent(
  client: Awaited<ReturnType<typeof getLLMClient>>,
  systemPrompt: string,
  userPrompt: string
): Promise<AgentResult> {
  const response = await client.chat([
    { role: "system", content: systemPrompt },
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

function clampInt(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, Math.round(value)))
}

function resolveSourcePolicy(
  source: string,
  sourceThresholds?: Record<string, SourceThresholdPolicy>
): SourceThresholdPolicy {
  if (!sourceThresholds || typeof sourceThresholds !== "object") return {}
  const key = source.trim().toLowerCase()
  return sourceThresholds[key] || sourceThresholds["*"] || {}
}

function computeEvidenceScore(input: {
  parseConfidence?: number
  fieldConfidence?: Record<string, number>
  sigmaMatched: boolean
  yaraMatched: boolean
  threatIntelHits: number
  indicatorCount: number
}): number {
  const parse = clampInt(Number(input.parseConfidence || 0), 0, 100)
  const fcValues = Object.values(input.fieldConfidence || {}).filter((v) => typeof v === "number")
  const avgField = fcValues.length ? Math.round(fcValues.reduce((a, b) => a + b, 0) / fcValues.length) : 0
  let score = Math.round(parse * 0.35 + avgField * 0.2)
  if (input.sigmaMatched) score += 20
  if (input.yaraMatched) score += 15
  score += Math.min(15, input.threatIntelHits * 3)
  score += Math.min(15, input.indicatorCount * 2)
  return clampInt(score, 0, 100)
}

function capWords(text: string, maxWords: number): string {
  const words = text
    .replace(/\s+/g, " ")
    .trim()
    .split(" ")
    .filter(Boolean)
  return words.slice(0, Math.max(1, maxWords)).join(" ")
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
    maxTokens: number
    temperature: number
    analysisAgents?: number
    agents?: LLMAgentConfig[]
    autoStatusConfidenceThreshold?: number
    verdictMaliciousThreshold?: number
    verdictSuspiciousThreshold?: number
    fpAutoResolveThreshold?: number
    neverAutoResolveLowEvidence?: boolean
    minAutoResolveEvidence?: number
    sourceThresholds?: Record<string, SourceThresholdPolicy>
  }>("llm", {
    provider: "openai",
    model: "gpt-4.1-nano",
    maxTokens: 700,
    temperature: 0.1,
    analysisAgents: 3,
    agents: DEFAULT_AGENTS,
    autoStatusConfidenceThreshold: 90,
    verdictMaliciousThreshold: 80,
    verdictSuspiciousThreshold: 45,
    fpAutoResolveThreshold: 30,
    neverAutoResolveLowEvidence: true,
    minAutoResolveEvidence: 55,
    sourceThresholds: {},
  })

  const indicators = extractIndicators([alert.title, alert.description, alert.rawLog].join("\n"))
  const historicalCases = await retrieveHistoricalCasesForAlert(alert, 8).catch(() => [])
  const historicalContext = formatHistoricalCasesForPrompt(historicalCases)
  // NOTE: Title, Description, YARA Match, and Sigma match data are intentionally
  // excluded from the AI agent context. Those fields are derived from detection rules
  // and can confuse agents about what the original raw log actually contains.
  const sharedContext = `
Alert ID: ${alert.id}
Timestamp: ${alert.timestamp}
Severity: ${alert.severity}
Source: ${alert.source}
Source IP: ${alert.sourceIp}
Destination IP: ${alert.destIp}
MITRE Tactic: ${alert.mitreTactic}
MITRE Technique: ${alert.mitreTechnique}
Raw Log: ${alert.rawLog.slice(0, 1200)}
Indicators:
- IPs: ${indicators.ips.join(", ") || "None"}
- URLs: ${indicators.urls.join(", ") || "None"}
- Domains: ${indicators.domains.join(", ") || "None"}
- Hashes: ${indicators.hashes.join(", ") || "None"}
- Filenames: ${indicators.filenames.join(", ") || "None"}
Threat Intel Snapshot:
${alert.enrichment.threatIntel || "No threat intel snapshot available."}

Historical Labeled Cases (RAG context):
${historicalContext}
`

  const maxAgentCalls = Math.max(1, Math.min(8, settings.analysisAgents || 3))
  const configuredAgents = normalizeAgentConfigs(settings.agents, {
    model: settings.model || "gpt-4.1-nano",
    maxTokens: settings.maxTokens || 700,
    temperature: settings.temperature || 0.1,
  })
  const summaryAgent = configuredAgents.find((a) => a.id === "summary_header" && a.enabled)
  const activeAgents = configuredAgents
    .filter((a) => a.id !== "summary_header")
    .filter((a) => a.enabled)
    .slice(0, maxAgentCalls)

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
  const usedModels = new Set<string>()

  try {
    const fallbackAgents = DEFAULT_AGENTS.filter((a) => a.id !== "summary_header")
    const agentsToRun = activeAgents.length > 0 ? activeAgents : fallbackAgents.slice(0, maxAgentCalls)
    for (const agent of agentsToRun) {
      try {
        const client = await getLLMClient({
          model: agent.model,
          maxTokens: agent.maxTokens,
          temperature: agent.temperature,
        })
        const systemPrompt = `${AGENT_OUTPUT_SCHEMA_PROMPT}\n\nAgent profile: ${agent.name}\nInstructions: ${agent.prompt}`
        const userPrompt = `${sharedContext}\nAgent objective: ${agent.prompt}`
        const result = await runAgent(client, systemPrompt, userPrompt)
        if (result.analysis) {
          agentResults.push(result)
          aiSuccessCount += 1
          usedModels.add(agent.model)
        }
      } catch (err) {
        systemLog("warn", "llm", "Agent call failed", { alertId, agentId: agent.id, error: String(err) })
        // Keep partial AI results from other agents; don't fail the whole enrichment.
      }
    }
  } catch (err) {
    systemLog("error", "llm", "Failed to initialize LLM client", { alertId, error: String(err) })
    // Client initialization failed; use fallback below.
  }

  let aiSummaryShort = ""
  if (summaryAgent) {
    try {
      const summaryClient = await getLLMClient({
        model: summaryAgent.model,
        maxTokens: summaryAgent.maxTokens,
        temperature: summaryAgent.temperature,
      })
      const summarySystem = `${AGENT_OUTPUT_SCHEMA_PROMPT}\n\nReturn analysis as a single sentence of no more than 30 words.`
      const summaryUser = `Role: ${summaryAgent.name}\nGoal: ${summaryAgent.prompt}\n${sharedContext}`
      const summaryResult = await runAgent(summaryClient, summarySystem, summaryUser)
      aiSummaryShort = capWords(summaryResult.analysis || "", 30)
      usedModels.add(summaryAgent.model)
    } catch (err) {
      systemLog("warn", "llm", "Summary agent call failed", { alertId, agentId: summaryAgent.id, error: String(err) })
    }
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

  if (!aiSummaryShort) {
    aiSummaryShort = capWords((agentResults[0]?.analysis || alert.description || heuristicFallback.analysis || "").replace(/^Agent\s+\d+:\s*/i, ""), 30)
  }

  const aiSeverities = agentResults
    .map((r) => r.severity)
    .filter((s): s is Severity => !!s)
  const recategorizedSeverity = aggregateSeverity(aiSeverities, alert.severity)
  // Heuristics score is a rule-based signal independent of LLM — use the alert's
  // own ingestion-time severity so a confused AI agent cannot drag it down.
  const heuristicsScore = computeHeuristicsScore({
    severity: alert.severity,
    indicators,
    hasThreatIntel: Boolean(alert.enrichment.threatIntel?.trim()),
    hasYaraMatch: Boolean(alert.yaraMatch),
  })

  await upsertEnrichment(alertId, {
    aiAnalysis: analyses.join("\n\n"),
    aiSummaryShort,
    iocType,
    recommendation,
    confidence: toNumberInRange(avgAiScore, alert.enrichment.aiScore || alert.enrichment.confidence || 0),
    aiScore: toNumberInRange(avgAiScore, alert.enrichment.aiScore || alert.enrichment.confidence || 0),
    heuristicsScore: toNumberInRange(heuristicsScore, alert.enrichment.heuristicsScore || 0),
    llmProvider: settings.provider,
    llmModel: usedModels.size > 0 ? Array.from(usedModels).join(", ") : settings.model || "gpt-4.1-nano",
  })

  const sourcePolicy = resolveSourcePolicy(alert.source, settings.sourceThresholds)
  const maliciousThreshold = clampInt(
    sourcePolicy.maliciousThreshold ?? settings.verdictMaliciousThreshold ?? 80,
    1,
    100
  )
  const suspiciousThreshold = clampInt(
    sourcePolicy.suspiciousThreshold ?? settings.verdictSuspiciousThreshold ?? 45,
    1,
    Math.max(1, maliciousThreshold - 1)
  )
  const fpAutoResolveThreshold = clampInt(
    sourcePolicy.fpAutoResolveThreshold ?? settings.fpAutoResolveThreshold ?? 30,
    0,
    Math.max(0, suspiciousThreshold - 1)
  )
  const minAutoResolveEvidence = clampInt(
    sourcePolicy.minAutoResolveEvidence ?? settings.minAutoResolveEvidence ?? 55,
    0,
    100
  )

  const threatIntelHits = (alert.enrichment.threatIntelVendors || []).filter((v) => v.hit).length
  const evidenceScore = computeEvidenceScore({
    parseConfidence: alert.enrichment.parseConfidence,
    fieldConfidence: alert.enrichment.fieldConfidence,
    sigmaMatched: Boolean(alert.enrichment.sigma),
    yaraMatched: Boolean(alert.yaraMatch),
    threatIntelHits,
    indicatorCount:
      indicators.ips.length +
      indicators.urls.length +
      indicators.domains.length +
      indicators.hashes.length +
      indicators.filenames.length,
  })

  const verdict: AlertVerdict =
    avgAiScore >= maliciousThreshold ? "malicious" : avgAiScore >= suspiciousThreshold ? "suspicious" : "false_positive"

  const previousVerdict = alert.verdict
  const verdictReason = [
    `verdict ${previousVerdict} -> ${verdict}`,
    `aiScore=${avgAiScore}`,
    `heuristics=${heuristicsScore}`,
    `evidence=${evidenceScore}`,
    `thresholds(malicious=${maliciousThreshold}, suspicious=${suspiciousThreshold}, fpAutoResolve<=${fpAutoResolveThreshold})`,
    `source=${alert.source}`,
    Object.keys(sourcePolicy).length > 0 ? "sourcePolicy=applied" : "sourcePolicy=default",
  ].join(" | ")
  const verdictFactors: Record<string, unknown> = {
    previousVerdict,
    newVerdict: verdict,
    scores: {
      aiScore: avgAiScore,
      heuristicsScore,
      parseConfidence: alert.enrichment.parseConfidence ?? 0,
      evidenceScore,
    },
    thresholds: {
      maliciousThreshold,
      suspiciousThreshold,
      fpAutoResolveThreshold,
      minAutoResolveEvidence,
    },
    detectorSignals: {
      sigmaMatched: Boolean(alert.enrichment.sigma),
      yaraMatched: Boolean(alert.yaraMatch),
      threatIntelHits,
    },
    fieldConfidence: alert.enrichment.fieldConfidence || {},
  }

  await updateAlertVerdict(alertId, verdict)
  await updateAlertSeverity(alertId, recategorizedSeverity)
  await upsertEnrichment(alertId, {
    verdictReason,
    verdictFactors,
  })

  try {
    const refreshed = await getAlertById(alertId)
    if (refreshed) await upsertAlertCaseToQdrant(refreshed)
  } catch (err) {
    systemLog("warn", "rag", "Failed to persist alert in Qdrant memory", { alertId, error: String(err) })
  }

  // Auto-resolve unassigned alerts that AI classifies as false positive with high assurance (low score)
  if (
    verdict === "false_positive" &&
    avgAiScore <= fpAutoResolveThreshold &&
    alert.incidentStatus === "unassigned" &&
    (!settings.neverAutoResolveLowEvidence || evidenceScore >= minAutoResolveEvidence)
  ) {
    await updateAlertIncidentStatus(alertId, "resolved")
    systemLog("info", "llm", "Auto-resolved alert as false positive", { alertId, avgAiScore, fpAutoResolveThreshold })
  } else if (
    verdict === "false_positive" &&
    avgAiScore <= fpAutoResolveThreshold &&
    alert.incidentStatus === "unassigned" &&
    settings.neverAutoResolveLowEvidence &&
    evidenceScore < minAutoResolveEvidence
  ) {
    systemLog("info", "llm", "Skipped auto-resolve due to low evidence policy", {
      alertId,
      evidenceScore,
      minAutoResolveEvidence,
    })
  }

  systemLog("info", "llm", "LLM enrichment completed", { alertId, avgAiScore, verdict })
}
