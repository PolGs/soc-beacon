import { getDb, persistDb } from "./index"
import type { Alert, AlertEnrichment, Severity, IncidentStatus, AlertVerdict } from "../types"
import { nanoid } from "nanoid"

function defaultScoreFromSeverity(severity: Severity): number {
  switch (severity) {
    case "critical":
      return 92
    case "high":
      return 78
    case "medium":
      return 62
    case "low":
      return 42
    default:
      return 24
  }
}

function normalizeSqliteTimestamp(value: string | undefined): string {
  if (!value) return new Date().toISOString()
  if (value.includes("T")) return value
  // sqlite datetime('now') format: YYYY-MM-DD HH:MM:SS (UTC, no suffix)
  return value.replace(" ", "T") + "Z"
}

function rowToAlert(row: Record<string, unknown>, enrichRow?: Record<string, unknown>): Alert {
  const severity = row.severity as Severity
  const fallbackScore = defaultScoreFromSeverity(severity)
  const enrichment: AlertEnrichment = enrichRow
    ? {
        aiAnalysis: (enrichRow.ai_analysis as string) || "",
        iocType: (enrichRow.ioc_type as string) || "",
        threatIntel: (enrichRow.threat_intel as string) || "",
        recommendation: (enrichRow.recommendation as string) || "",
        aiScore: (enrichRow.ai_score as number) || (enrichRow.confidence as number) || fallbackScore,
        heuristicsScore: (enrichRow.heuristics_score as number) || fallbackScore,
        confidence: (enrichRow.confidence as number) || fallbackScore,
        relatedCves: enrichRow.related_cves ? JSON.parse(enrichRow.related_cves as string) : [],
        geoLocation:
          enrichRow.geo_country
            ? { country: enrichRow.geo_country as string, city: (enrichRow.geo_city as string) || "" }
            : null,
        asnInfo: (enrichRow.asn_info as string) || null,
        parseConfidence: typeof enrichRow.parse_confidence === "number" ? (enrichRow.parse_confidence as number) : undefined,
        sigma: enrichRow.sigma_match ? JSON.parse(enrichRow.sigma_match as string) : null,
      }
    : {
        aiAnalysis: "",
        iocType: "",
        threatIntel: "",
        recommendation: "",
        aiScore: fallbackScore,
        heuristicsScore: fallbackScore,
        confidence: fallbackScore,
        relatedCves: [],
        geoLocation: null,
        asnInfo: null,
        parseConfidence: undefined,
        sigma: null,
      }

  return {
    id: row.id as string,
    timestamp: row.timestamp as string,
    ingestedAt: normalizeSqliteTimestamp(row.created_at as string | undefined),
    source: row.source as string,
    sourceIp: row.source_ip as string,
    destIp: row.dest_ip as string,
    severity,
    title: row.title as string,
    description: row.description as string,
    yaraMatch: (row.yara_match as string) || null,
    mitreTactic: row.mitre_tactic as string,
    mitreTechnique: row.mitre_technique as string,
    incidentStatus: (row.incident_status as IncidentStatus) || "unassigned",
    verdict: (row.verdict as AlertVerdict) || "suspicious",
    enrichment,
    rawLog: row.raw_log as string,
  }
}

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

export async function getAlerts(filters?: {
  severity?: string
  incidentStatus?: string
  verdict?: string
  search?: string
  limit?: number
  offset?: number
}): Promise<Alert[]> {
  const db = await getDb()
  let sql = `SELECT a.*, e.ai_analysis, e.ioc_type, e.threat_intel, e.recommendation, e.confidence, e.ai_score, e.heuristics_score, e.related_cves, e.geo_country, e.geo_city, e.asn_info, e.sigma_match, e.parse_confidence
    FROM alerts a LEFT JOIN alert_enrichments e ON a.id = e.alert_id WHERE 1=1`
  const params: unknown[] = []

  if (filters?.severity && filters.severity !== "all") {
    sql += ` AND a.severity = ?`
    params.push(filters.severity)
  }
  if (filters?.incidentStatus && filters.incidentStatus !== "all") {
    sql += ` AND a.incident_status = ?`
    params.push(filters.incidentStatus)
  }
  if (filters?.verdict && filters.verdict !== "all") {
    sql += ` AND a.verdict = ?`
    params.push(filters.verdict)
  }
  if (filters?.search) {
    sql += ` AND (a.title LIKE ? OR a.source LIKE ? OR a.source_ip LIKE ? OR a.dest_ip LIKE ? OR a.mitre_technique LIKE ?)`
    const term = `%${filters.search}%`
    params.push(term, term, term, term, term)
  }
  sql += ` ORDER BY a.timestamp DESC`
  if (filters?.limit) {
    sql += ` LIMIT ?`
    params.push(filters.limit)
  }
  if (filters?.offset) {
    sql += ` OFFSET ?`
    params.push(filters.offset)
  }

  const rows = stmtToObjects(db, sql, params)
  return rows.map((row) => rowToAlert(row, row))
}

export async function getAlertById(id: string): Promise<Alert | null> {
  const db = await getDb()
  const rows = stmtToObjects(
    db,
    `SELECT a.*, e.ai_analysis, e.ioc_type, e.threat_intel, e.recommendation, e.confidence, e.ai_score, e.heuristics_score, e.related_cves, e.geo_country, e.geo_city, e.asn_info, e.sigma_match, e.parse_confidence
     FROM alerts a LEFT JOIN alert_enrichments e ON a.id = e.alert_id WHERE a.id = ?`,
    [id]
  )
  if (rows.length === 0) return null
  return rowToAlert(rows[0], rows[0])
}

export async function createAlert(data: {
  timestamp: string; source: string; sourceIp: string; destIp: string;
  severity: Severity; title: string; description: string;
  yaraMatch: string | null; mitreTactic: string; mitreTechnique: string;
  incidentStatus: IncidentStatus; verdict: AlertVerdict; rawLog: string; logId?: string;
}): Promise<string> {
  const db = await getDb()
  const id = `ALR-${nanoid(8).toUpperCase()}`
  db.run(
    `INSERT INTO alerts (id, timestamp, source, source_ip, dest_ip, severity, title, description, yara_match, mitre_tactic, mitre_technique, status, incident_status, verdict, raw_log, log_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id, data.timestamp, data.source, data.sourceIp, data.destIp, data.severity, data.title, data.description,
      data.yaraMatch, data.mitreTactic, data.mitreTechnique, "new", data.incidentStatus, data.verdict, data.rawLog, data.logId || null,
    ]
  )
  persistDb()
  return id
}

export async function updateAlertIncidentStatus(id: string, incidentStatus: IncidentStatus): Promise<void> {
  const legacyStatus = incidentStatus === "in_progress" ? "investigating" : incidentStatus === "resolved" ? "resolved" : "new"
  const db = await getDb()
  db.run(
    "UPDATE alerts SET incident_status = ?, status = ?, updated_at = datetime('now') WHERE id = ?",
    [incidentStatus, legacyStatus, id]
  )
  persistDb()
}

export async function updateAlertVerdict(id: string, verdict: AlertVerdict): Promise<void> {
  const db = await getDb()
  db.run("UPDATE alerts SET verdict = ?, updated_at = datetime('now') WHERE id = ?", [verdict, id])
  persistDb()
}

export async function updateAlertSeverity(id: string, severity: Severity): Promise<void> {
  const db = await getDb()
  db.run("UPDATE alerts SET severity = ?, updated_at = datetime('now') WHERE id = ?", [severity, id])
  persistDb()
}

export async function deleteAlert(id: string): Promise<void> {
  const db = await getDb()
  db.run("DELETE FROM alert_enrichments WHERE alert_id = ?", [id])
  db.run("DELETE FROM alerts WHERE id = ?", [id])
  persistDb()
}

export async function getAlertCounts(): Promise<{
  severity: Record<string, number>
  status: Record<string, number>
  total: number
}> {
  const db = await getDb()
  const sevRows = stmtToObjects(db, "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
  const statusRows = stmtToObjects(db, "SELECT incident_status as status, COUNT(*) as count FROM alerts GROUP BY incident_status")
  const totalRows = stmtToObjects(db, "SELECT COUNT(*) as count FROM alerts")

  const severity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const r of sevRows) severity[r.severity as string] = r.count as number

  const status: Record<string, number> = { unassigned: 0, in_progress: 0, resolved: 0 }
  for (const r of statusRows) status[r.status as string] = r.count as number

  return { severity, status, total: (totalRows[0]?.count as number) || 0 }
}

export async function getTimelineData(hours = 24): Promise<Array<{ time: string; critical: number; high: number; medium: number; low: number }>> {
  const db = await getDb()
  const since = new Date(Date.now() - hours * 3600000).toISOString()
  const rows = stmtToObjects(
    db,
    `SELECT strftime('%H:00', timestamp) as time_slot, severity, COUNT(*) as count
     FROM alerts WHERE timestamp >= ? GROUP BY time_slot, severity ORDER BY time_slot`,
    [since]
  )

  const buckets: Record<string, { critical: number; high: number; medium: number; low: number }> = {}
  for (let i = 0; i < 24; i += 2) {
    const t = `${String(i).padStart(2, "0")}:00`
    buckets[t] = { critical: 0, high: 0, medium: 0, low: 0 }
  }

  for (const r of rows) {
    const slot = r.time_slot as string
    const hourNum = parseInt(slot.split(":")[0])
    const bucket = `${String(Math.floor(hourNum / 2) * 2).padStart(2, "0")}:00`
    if (buckets[bucket] && r.severity !== "info") {
      buckets[bucket][r.severity as keyof typeof buckets[string]] += r.count as number
    }
  }

  return Object.entries(buckets).map(([time, counts]) => ({ time, ...counts }))
}

export async function getSourceDistribution(): Promise<Array<{ name: string; value: number }>> {
  const db = await getDb()
  const rows = stmtToObjects(
    db,
    `SELECT source, COUNT(*) as count FROM alerts GROUP BY source ORDER BY count DESC LIMIT 10`
  )
  const total = rows.reduce((sum, r) => sum + (r.count as number), 0)
  return rows.map((r) => ({
    name: (r.source as string).replace(/-\d+$/, ""),
    value: total > 0 ? Math.round(((r.count as number) / total) * 100) : 0,
  }))
}

export async function getTopMitreTechniques(limit = 8): Promise<Array<{ technique: string; count: number }>> {
  const db = await getDb()
  const rows = stmtToObjects(
    db,
    `SELECT mitre_technique as technique, COUNT(*) as count FROM alerts WHERE mitre_technique != '' AND mitre_technique != 'Unknown' GROUP BY mitre_technique ORDER BY count DESC LIMIT ?`,
    [limit]
  )
  return rows.map((r) => ({
    technique: (r.technique as string).split(" - ")[0],
    count: r.count as number,
  }))
}
