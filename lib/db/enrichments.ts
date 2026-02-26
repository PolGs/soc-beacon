import { getDb, persistDb } from "./index"
import type { AlertEnrichment, SigmaMatch, ThreatIntelVendorResult } from "../types"

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
    aiSummaryShort: (r.ai_summary_short as string) || undefined,
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
    parseConfidence: typeof r.parse_confidence === "number" ? (r.parse_confidence as number) : undefined,
    extractedFields: r.extracted_fields ? JSON.parse(r.extracted_fields as string) : undefined,
    fieldConfidence: r.field_confidence ? JSON.parse(r.field_confidence as string) : undefined,
    verdictReason: (r.verdict_reason as string) || undefined,
    verdictFactors: r.verdict_factors ? JSON.parse(r.verdict_factors as string) : undefined,
    sigma: r.sigma_match ? JSON.parse(r.sigma_match as string) : null,
    threatIntelVendors: r.threat_intel_vendors ? JSON.parse(r.threat_intel_vendors as string) : undefined,
  }
}

export async function upsertEnrichment(
  alertId: string,
  data: Partial<{
    aiAnalysis: string
    aiSummaryShort: string
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
    sigmaMatch: SigmaMatch | null
    parseConfidence: number
    extractedFields: Record<string, unknown>
    fieldConfidence: Record<string, number>
    verdictReason: string
    verdictFactors: Record<string, unknown>
    llmProvider: string
    llmModel: string
    threatIntelVendors: ThreatIntelVendorResult[]
  }>
): Promise<void> {
  const db = await getDb()
  const existing = stmtToObjects(db, "SELECT alert_id FROM alert_enrichments WHERE alert_id = ?", [alertId])

  if (existing.length > 0) {
    const updates: string[] = []
    const params: unknown[] = []
    if (data.aiAnalysis !== undefined) { updates.push("ai_analysis = ?"); params.push(data.aiAnalysis) }
    if (data.aiSummaryShort !== undefined) { updates.push("ai_summary_short = ?"); params.push(data.aiSummaryShort) }
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
    if (data.sigmaMatch !== undefined) { updates.push("sigma_match = ?"); params.push(data.sigmaMatch ? JSON.stringify(data.sigmaMatch) : null) }
    if (data.parseConfidence !== undefined) { updates.push("parse_confidence = ?"); params.push(data.parseConfidence) }
    if (data.extractedFields !== undefined) { updates.push("extracted_fields = ?"); params.push(JSON.stringify(data.extractedFields)) }
    if (data.fieldConfidence !== undefined) { updates.push("field_confidence = ?"); params.push(JSON.stringify(data.fieldConfidence)) }
    if (data.verdictReason !== undefined) { updates.push("verdict_reason = ?"); params.push(data.verdictReason) }
    if (data.verdictFactors !== undefined) { updates.push("verdict_factors = ?"); params.push(JSON.stringify(data.verdictFactors)) }
    if (data.llmProvider !== undefined) { updates.push("llm_provider = ?"); params.push(data.llmProvider) }
    if (data.llmModel !== undefined) { updates.push("llm_model = ?"); params.push(data.llmModel) }
    if (data.threatIntelVendors !== undefined) { updates.push("threat_intel_vendors = ?"); params.push(JSON.stringify(data.threatIntelVendors)) }
    updates.push("enriched_at = datetime('now')")

    if (updates.length > 1) {
      params.push(alertId)
      db.run(`UPDATE alert_enrichments SET ${updates.join(", ")} WHERE alert_id = ?`, params)
    }
  } else {
    db.run(
      `INSERT INTO alert_enrichments (alert_id, ai_analysis, ai_summary_short, ioc_type, threat_intel, recommendation, confidence, ai_score, heuristics_score, related_cves, geo_country, geo_city, asn_info, sigma_match, parse_confidence, extracted_fields, field_confidence, verdict_reason, verdict_factors, llm_provider, llm_model, threat_intel_vendors)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        alertId,
        data.aiAnalysis || null,
        data.aiSummaryShort || null,
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
        data.sigmaMatch ? JSON.stringify(data.sigmaMatch) : null,
        data.parseConfidence ?? null,
        data.extractedFields ? JSON.stringify(data.extractedFields) : null,
        data.fieldConfidence ? JSON.stringify(data.fieldConfidence) : null,
        data.verdictReason || null,
        data.verdictFactors ? JSON.stringify(data.verdictFactors) : null,
        data.llmProvider || null,
        data.llmModel || null,
        data.threatIntelVendors ? JSON.stringify(data.threatIntelVendors) : null,
      ]
    )
  }
  persistDb()
}
