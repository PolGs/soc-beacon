import { getDb, persistDb } from "./index"
import type { AlertEnrichment } from "../types"

function stmtToObjects(db: Awaited<ReturnType<typeof getDb>>, sql: string, params: unknown[] = []): Record<string, unknown>[] {
  const stmt = db.prepare(sql)
  if (params.length) stmt.bind(params)
  const results: Record<string, unknown>[] = []
  while (stmt.step()) {
    results.push(stmt.getAsObject())
  }
  stmt.free()
  return results
}

export async function getEnrichment(alertId: string): Promise<AlertEnrichment | null> {
  const db = await getDb()
  const rows = stmtToObjects(db, "SELECT * FROM alert_enrichments WHERE alert_id = ?", [alertId])
  if (rows.length === 0) return null

  const r = rows[0]
  return {
    aiAnalysis: (r.ai_analysis as string) || "",
    iocType: (r.ioc_type as string) || "",
    threatIntel: (r.threat_intel as string) || "",
    recommendation: (r.recommendation as string) || "",
    aiScore: (r.ai_score as number) || (r.confidence as number) || 0,
    heuristicsScore: (r.heuristics_score as number) || (r.confidence as number) || 0,
    confidence: (r.confidence as number) || 0,
    relatedCves: r.related_cves ? JSON.parse(r.related_cves as string) : [],
    geoLocation: r.geo_country
      ? { country: r.geo_country as string, city: (r.geo_city as string) || "" }
      : null,
    asnInfo: (r.asn_info as string) || null,
  }
}

export async function upsertEnrichment(
  alertId: string,
  data: Partial<{
    aiAnalysis: string
    iocType: string
    threatIntel: string
    recommendation: string
    confidence: number
    aiScore: number
    heuristicsScore: number
    relatedCves: string[]
    geoCountry: string
    geoCity: string
    asnInfo: string
    llmProvider: string
    llmModel: string
  }>
): Promise<void> {
  const db = await getDb()
  const existing = stmtToObjects(db, "SELECT alert_id FROM alert_enrichments WHERE alert_id = ?", [alertId])

  if (existing.length > 0) {
    const updates: string[] = []
    const params: unknown[] = []
    if (data.aiAnalysis !== undefined) { updates.push("ai_analysis = ?"); params.push(data.aiAnalysis) }
    if (data.iocType !== undefined) { updates.push("ioc_type = ?"); params.push(data.iocType) }
    if (data.threatIntel !== undefined) { updates.push("threat_intel = ?"); params.push(data.threatIntel) }
    if (data.recommendation !== undefined) { updates.push("recommendation = ?"); params.push(data.recommendation) }
    if (data.confidence !== undefined) { updates.push("confidence = ?"); params.push(data.confidence) }
    if (data.aiScore !== undefined) { updates.push("ai_score = ?"); params.push(data.aiScore) }
    if (data.heuristicsScore !== undefined) { updates.push("heuristics_score = ?"); params.push(data.heuristicsScore) }
    if (data.relatedCves !== undefined) { updates.push("related_cves = ?"); params.push(JSON.stringify(data.relatedCves)) }
    if (data.geoCountry !== undefined) { updates.push("geo_country = ?"); params.push(data.geoCountry) }
    if (data.geoCity !== undefined) { updates.push("geo_city = ?"); params.push(data.geoCity) }
    if (data.asnInfo !== undefined) { updates.push("asn_info = ?"); params.push(data.asnInfo) }
    if (data.llmProvider !== undefined) { updates.push("llm_provider = ?"); params.push(data.llmProvider) }
    if (data.llmModel !== undefined) { updates.push("llm_model = ?"); params.push(data.llmModel) }
    updates.push("enriched_at = datetime('now')")

    if (updates.length > 1) {
      params.push(alertId)
      db.run(`UPDATE alert_enrichments SET ${updates.join(", ")} WHERE alert_id = ?`, params)
    }
  } else {
    db.run(
      `INSERT INTO alert_enrichments (alert_id, ai_analysis, ioc_type, threat_intel, recommendation, confidence, ai_score, heuristics_score, related_cves, geo_country, geo_city, asn_info, llm_provider, llm_model)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        alertId,
        data.aiAnalysis || null,
        data.iocType || null,
        data.threatIntel || null,
        data.recommendation || null,
        data.confidence || null,
        data.aiScore || null,
        data.heuristicsScore || null,
        data.relatedCves ? JSON.stringify(data.relatedCves) : null,
        data.geoCountry || null,
        data.geoCity || null,
        data.asnInfo || null,
        data.llmProvider || null,
        data.llmModel || null,
      ]
    )
  }
  persistDb()
}
