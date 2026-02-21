import { getDb, persistDb } from "./index"
import type { LogEntry, Severity } from "../types"
import { nanoid } from "nanoid"

function rowToLog(row: Record<string, unknown>): LogEntry {
  return {
    id: row.id as string,
    timestamp: row.timestamp as string,
    source: row.source as string,
    message: row.message as string,
    severity: row.severity as Severity,
    parsed: !!(row.parsed as number),
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

export async function getLogs(filters?: {
  severity?: string
  source?: string
  search?: string
  limit?: number
  offset?: number
}): Promise<LogEntry[]> {
  const db = await getDb()
  let sql = "SELECT * FROM logs WHERE 1=1"
  const params: unknown[] = []

  if (filters?.severity && filters.severity !== "all") {
    sql += " AND severity = ?"
    params.push(filters.severity)
  }
  if (filters?.source && filters.source !== "All") {
    sql += " AND source LIKE ?"
    params.push(`%${filters.source}%`)
  }
  if (filters?.search) {
    sql += " AND (message LIKE ? OR source LIKE ? OR id LIKE ?)"
    const term = `%${filters.search}%`
    params.push(term, term, term)
  }
  sql += " ORDER BY timestamp DESC"
  if (filters?.limit) {
    sql += " LIMIT ?"
    params.push(filters.limit)
  }
  if (filters?.offset) {
    sql += " OFFSET ?"
    params.push(filters.offset)
  }

  return stmtToObjects(db, sql, params).map(rowToLog)
}

export async function getLogById(id: string): Promise<LogEntry | null> {
  const db = await getDb()
  const rows = stmtToObjects(db, "SELECT * FROM logs WHERE id = ?", [id])
  if (rows.length === 0) return null
  return rowToLog(rows[0])
}

export async function createLog(data: {
  timestamp: string
  source: string
  message: string
  severity: Severity
  parsed?: boolean
  raw?: string
}): Promise<string> {
  const db = await getDb()
  const id = `LOG-${nanoid(8).toUpperCase()}`
  db.run(
    "INSERT INTO logs (id, timestamp, source, message, severity, parsed, raw) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [id, data.timestamp, data.source, data.message, data.severity, data.parsed ? 1 : 0, data.raw || null]
  )
  persistDb()
  return id
}

export async function createLogsBatch(
  logs: Array<{
    timestamp: string
    source: string
    message: string
    severity: Severity
    parsed?: boolean
    raw?: string
  }>
): Promise<string[]> {
  const db = await getDb()
  const ids: string[] = []
  const stmt = db.prepare(
    "INSERT INTO logs (id, timestamp, source, message, severity, parsed, raw) VALUES (?, ?, ?, ?, ?, ?, ?)"
  )
  for (const log of logs) {
    const id = `LOG-${nanoid(8).toUpperCase()}`
    stmt.run([id, log.timestamp, log.source, log.message, log.severity, log.parsed ? 1 : 0, log.raw || null])
    ids.push(id)
  }
  stmt.free()
  persistDb()
  return ids
}

export async function getLogCount(): Promise<number> {
  const db = await getDb()
  const rows = stmtToObjects(db, "SELECT COUNT(*) as count FROM logs")
  return (rows[0]?.count as number) || 0
}

export async function getLogSources(): Promise<string[]> {
  const db = await getDb()
  const rows = stmtToObjects(db, "SELECT DISTINCT source FROM logs ORDER BY source")
  return rows.map((r) => r.source as string)
}

export async function getLogStats(): Promise<{ total: number; parsed: number; severityCounts: Record<string, number> }> {
  const db = await getDb()
  const totalRows = stmtToObjects(db, "SELECT COUNT(*) as count FROM logs")
  const parsedRows = stmtToObjects(db, "SELECT COUNT(*) as count FROM logs WHERE parsed = 1")
  const sevRows = stmtToObjects(db, "SELECT severity, COUNT(*) as count FROM logs GROUP BY severity")

  const severityCounts: Record<string, number> = {}
  for (const r of sevRows) severityCounts[r.severity as string] = r.count as number

  return {
    total: (totalRows[0]?.count as number) || 0,
    parsed: (parsedRows[0]?.count as number) || 0,
    severityCounts,
  }
}
