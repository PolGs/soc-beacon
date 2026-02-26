import OpenAI from "openai"
import { getSetting } from "@/lib/db/settings"
import { getLabeledAlertsForRag } from "@/lib/db/alerts"
import { extractIndicators } from "@/lib/indicators"
import { systemLog } from "@/lib/system-log"
import type { Alert } from "@/lib/types"

const QDRANT_COLLECTION = process.env.QDRANT_COLLECTION || "soc_beacon_alert_memory"
const EMBEDDING_MODEL = process.env.RAG_EMBEDDING_MODEL || "text-embedding-3-small"

export interface HistoricalCase {
  id: string
  timestamp: string
  verdict: "true_positive" | "false_positive"
  severity: string
  title: string
  source: string
  sourceIp: string
  destIp: string
  aiScore?: number
  recommendation?: string
  reason: string
}

function isQdrantConfigured(): boolean {
  return Boolean(process.env.QDRANT_URL && process.env.QDRANT_URL.trim())
}

function getQdrantUrl(path: string): string {
  const base = (process.env.QDRANT_URL || "").replace(/\/+$/, "")
  return `${base}${path}`
}

function qdrantHeaders(): Record<string, string> {
  const headers: Record<string, string> = { "Content-Type": "application/json" }
  const apiKey = process.env.QDRANT_API_KEY?.trim()
  if (apiKey) headers["api-key"] = apiKey
  return headers
}

function toVerdictTag(verdict: string): "true_positive" | "false_positive" {
  return verdict === "false_positive" ? "false_positive" : "true_positive"
}

function buildAlertMemoryText(alert: Alert): string {
  return [
    `alert_id=${alert.id}`,
    `timestamp=${alert.timestamp}`,
    `source=${alert.source}`,
    `severity=${alert.severity}`,
    `verdict=${toVerdictTag(alert.verdict)}`,
    `title=${alert.title}`,
    `description=${alert.description}`,
    `source_ip=${alert.sourceIp}`,
    `dest_ip=${alert.destIp}`,
    `mitre_tactic=${alert.mitreTactic}`,
    `mitre_technique=${alert.mitreTechnique}`,
    `yara=${alert.yaraMatch || "none"}`,
    `raw=${alert.rawLog.slice(0, 1200)}`,
    `threat_intel=${alert.enrichment.threatIntel || ""}`,
    `recommendation=${alert.enrichment.recommendation || ""}`,
  ].join("\n")
}

async function getOpenAIEmbeddingClient(): Promise<OpenAI | null> {
  const llm = await getSetting<{ provider?: string; apiKey?: string }>("llm", {})
  const envKey = (process.env.OPENAI_API_KEY || "").trim()
  const settingKey = (llm.apiKey || "").trim()
  const apiKey =
    llm.provider === "openai"
      ? (settingKey || envKey)
      : envKey
  if (!apiKey) return null
  return new OpenAI({ apiKey })
}

async function embedText(text: string): Promise<number[] | null> {
  try {
    const client = await getOpenAIEmbeddingClient()
    if (!client) return null
    const response = await client.embeddings.create({
      model: EMBEDDING_MODEL,
      input: text.slice(0, 8000),
    })
    return response.data[0]?.embedding || null
  } catch (err) {
    systemLog("warn", "rag", "Embedding generation failed", { error: String(err) })
    return null
  }
}

async function ensureCollection(vectorSize: number): Promise<void> {
  const url = getQdrantUrl(`/collections/${QDRANT_COLLECTION}`)
  const exists = await fetch(url, { method: "GET", headers: qdrantHeaders() })
  if (exists.ok) return

  await fetch(url, {
    method: "PUT",
    headers: qdrantHeaders(),
    body: JSON.stringify({
      vectors: {
        size: vectorSize,
        distance: "Cosine",
      },
    }),
  })
}

export async function upsertAlertCaseToQdrant(alert: Alert): Promise<void> {
  if (!isQdrantConfigured()) return
  if (alert.verdict !== "malicious" && alert.verdict !== "false_positive") return

  const vector = await embedText(buildAlertMemoryText(alert))
  if (!vector) return

  try {
    await ensureCollection(vector.length)
    await fetch(getQdrantUrl(`/collections/${QDRANT_COLLECTION}/points`), {
      method: "PUT",
      headers: qdrantHeaders(),
      body: JSON.stringify({
        points: [
          {
            id: alert.id,
            vector,
            payload: {
              alert_id: alert.id,
              verdict: toVerdictTag(alert.verdict),
              severity: alert.severity,
              title: alert.title,
              source: alert.source,
              source_ip: alert.sourceIp,
              dest_ip: alert.destIp,
              recommendation: alert.enrichment.recommendation || "",
              ai_score: alert.enrichment.aiScore || 0,
              timestamp: alert.timestamp,
              text: buildAlertMemoryText(alert),
            },
          },
        ],
      }),
    })
  } catch (err) {
    systemLog("warn", "rag", "Failed to upsert case to Qdrant", { alertId: alert.id, error: String(err) })
  }
}

function fallbackCasesFromAlerts(alerts: Alert[], current: Alert, limit: number): HistoricalCase[] {
  const currentIndicators = extractIndicators(`${current.rawLog}\n${current.description}\n${current.title}`)
  const curIpSet = new Set([current.sourceIp, current.destIp, ...currentIndicators.ips].filter(Boolean))
  const curDomainSet = new Set(currentIndicators.domains)

  const scored = alerts
    .filter((a) => a.id !== current.id)
    .map((a) => {
      const indicators = extractIndicators(`${a.rawLog}\n${a.description}\n${a.title}`)
      let score = 0
      if (a.source === current.source) score += 3
      if (a.mitreTechnique === current.mitreTechnique) score += 2
      if (a.severity === current.severity) score += 1
      if (curIpSet.has(a.sourceIp) || curIpSet.has(a.destIp)) score += 4
      if (indicators.ips.some((ip) => curIpSet.has(ip))) score += 3
      if (indicators.domains.some((d) => curDomainSet.has(d))) score += 3
      return { a, score }
    })
    .filter((x) => x.score > 0)
    .sort((x, y) => y.score - x.score)
    .slice(0, limit)

  return scored.map(({ a, score }) => ({
    id: a.id,
    timestamp: a.timestamp,
    verdict: toVerdictTag(a.verdict),
    severity: a.severity,
    title: a.title,
    source: a.source,
    sourceIp: a.sourceIp,
    destIp: a.destIp,
    aiScore: a.enrichment.aiScore,
    recommendation: a.enrichment.recommendation,
    reason: `fallback_similarity_score=${score}`,
  }))
}

export async function retrieveHistoricalCasesForAlert(alert: Alert, limit = 8): Promise<HistoricalCase[]> {
  const localLabeled = await getLabeledAlertsForRag(250)
  if (!isQdrantConfigured()) {
    return fallbackCasesFromAlerts(localLabeled, alert, limit)
  }

  const vector = await embedText(buildAlertMemoryText(alert))
  if (!vector) {
    return fallbackCasesFromAlerts(localLabeled, alert, limit)
  }

  try {
    const response = await fetch(getQdrantUrl(`/collections/${QDRANT_COLLECTION}/points/search`), {
      method: "POST",
      headers: qdrantHeaders(),
      body: JSON.stringify({
        vector,
        limit: Math.max(1, Math.min(20, limit)),
        with_payload: true,
      }),
    })
    if (!response.ok) {
      return fallbackCasesFromAlerts(localLabeled, alert, limit)
    }

    const json = await response.json() as {
      result?: Array<{ score?: number; payload?: Record<string, unknown> }>
    }

    const cases: HistoricalCase[] = []
    for (const item of json.result || []) {
      const p = item.payload || {}
      const id = String(p.alert_id || "")
      if (!id || id === alert.id) continue
      const verdictRaw = String(p.verdict || "true_positive")
      cases.push({
        id,
        timestamp: String(p.timestamp || ""),
        verdict: verdictRaw === "false_positive" ? "false_positive" : "true_positive",
        severity: String(p.severity || "info"),
        title: String(p.title || ""),
        source: String(p.source || ""),
        sourceIp: String(p.source_ip || ""),
        destIp: String(p.dest_ip || ""),
        ...(typeof p.ai_score === "number" ? { aiScore: p.ai_score } : {}),
        recommendation: String(p.recommendation || ""),
        reason: `qdrant_score=${Number(item.score || 0).toFixed(3)}`,
      })
    }

    if (cases.length > 0) return cases
    return fallbackCasesFromAlerts(localLabeled, alert, limit)
  } catch (err) {
    systemLog("warn", "rag", "Qdrant search failed, using local fallback", { error: String(err) })
    return fallbackCasesFromAlerts(localLabeled, alert, limit)
  }
}

export function formatHistoricalCasesForPrompt(cases: HistoricalCase[]): string {
  if (cases.length === 0) return "No relevant historical labeled cases found."
  return cases
    .map((c, i) => {
      return [
        `${i + 1}. Alert ${c.id} (${c.timestamp})`,
        `- verdict: ${c.verdict}`,
        `- severity: ${c.severity}`,
        `- source: ${c.source} (${c.sourceIp} -> ${c.destIp})`,
        `- title: ${c.title}`,
        `- aiScore: ${typeof c.aiScore === "number" ? c.aiScore : "n/a"}`,
        `- prior_action: ${c.recommendation || "n/a"}`,
        `- retrieval_reason: ${c.reason}`,
      ].join("\n")
    })
    .join("\n\n")
}
