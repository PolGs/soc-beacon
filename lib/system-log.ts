type LogLevel = "debug" | "info" | "warn" | "error"

export interface SystemLogEntry {
  id: string
  ts: string
  level: LogLevel
  source: string
  message: string
  meta?: Record<string, unknown>
}

const MAX_LOGS = 500
const buffer: SystemLogEntry[] = []

function push(entry: SystemLogEntry) {
  buffer.push(entry)
  if (buffer.length > MAX_LOGS) {
    buffer.splice(0, buffer.length - MAX_LOGS)
  }
}

function normalizeMeta(meta?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!meta) return undefined
  try {
    JSON.stringify(meta)
    return meta
  } catch {
    return { note: "meta serialization failed" }
  }
}

export function systemLog(level: LogLevel, source: string, message: string, meta?: Record<string, unknown>) {
  push({
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    ts: new Date().toISOString(),
    level,
    source,
    message,
    meta: normalizeMeta(meta),
  })
}

export function getSystemLogs(limit = 200, since?: string): SystemLogEntry[] {
  const normalizedLimit = Math.max(1, Math.min(500, limit))
  let items = buffer
  if (since) {
    items = items.filter((entry) => entry.ts > since)
  }
  return items.slice(-normalizedLimit)
}

export function clearSystemLogs() {
  buffer.length = 0
}
