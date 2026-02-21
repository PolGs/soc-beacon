import type { Severity } from "@/lib/types"

interface ParsedLog {
  timestamp?: string
  source: string
  message: string
  severity?: Severity
}

function detectSeverity(message: string): Severity {
  const lower = message.toLowerCase()
  if (/critical|emergency|fatal|panic/.test(lower)) return "critical"
  if (/error|fail|denied|attack|alert|breach/.test(lower)) return "high"
  if (/warn|warning|suspicious|unusual/.test(lower)) return "medium"
  if (/notice|info|success|accept/.test(lower)) return "low"
  return "info"
}

function tryParseTimestamp(value: string): string | undefined {
  const date = new Date(value)
  if (!isNaN(date.getTime())) return date.toISOString()
  return undefined
}

export function parseCSVLogs(content: string): ParsedLog[] {
  const lines = content.trim().split("\n")
  if (lines.length < 2) return []

  const headers = lines[0].split(",").map((h) => h.trim().toLowerCase().replace(/['"]/g, ""))
  const results: ParsedLog[] = []

  // Find column indices
  const timestampIdx = headers.findIndex((h) =>
    /time|date|timestamp|ts|created/.test(h)
  )
  const sourceIdx = headers.findIndex((h) =>
    /source|src|origin|host|device|system/.test(h)
  )
  const messageIdx = headers.findIndex((h) =>
    /message|msg|log|event|description|detail|content/.test(h)
  )
  const severityIdx = headers.findIndex((h) =>
    /severity|level|priority|sev/.test(h)
  )

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim()
    if (!line) continue

    // Simple CSV split (handles basic quoting)
    const cols = splitCSVLine(line)

    const message = messageIdx >= 0 ? cols[messageIdx] : cols.join(" ")
    if (!message) continue

    results.push({
      timestamp: timestampIdx >= 0 ? tryParseTimestamp(cols[timestampIdx]) : undefined,
      source: sourceIdx >= 0 ? cols[sourceIdx] || "CSV-Import" : "CSV-Import",
      message,
      severity: severityIdx >= 0 ? mapSeverity(cols[severityIdx]) : detectSeverity(message),
    })
  }

  return results
}

function splitCSVLine(line: string): string[] {
  const result: string[] = []
  let current = ""
  let inQuotes = false

  for (let i = 0; i < line.length; i++) {
    const ch = line[i]
    if (ch === '"') {
      inQuotes = !inQuotes
    } else if (ch === "," && !inQuotes) {
      result.push(current.trim())
      current = ""
    } else {
      current += ch
    }
  }
  result.push(current.trim())
  return result
}

function mapSeverity(value: string): Severity {
  const lower = (value || "").toLowerCase().trim()
  if (["critical", "crit", "emergency", "emerg", "0", "1"].includes(lower)) return "critical"
  if (["high", "error", "err", "alert", "2", "3"].includes(lower)) return "high"
  if (["medium", "warning", "warn", "4", "5"].includes(lower)) return "medium"
  if (["low", "notice", "6"].includes(lower)) return "low"
  return "info"
}

export function parseJSONLogs(content: string): ParsedLog[] {
  const results: ParsedLog[] = []

  // Try as JSON array first
  try {
    const parsed = JSON.parse(content)
    if (Array.isArray(parsed)) {
      for (const entry of parsed) {
        const log = extractLogFromObject(entry)
        if (log) results.push(log)
      }
      return results
    }
    // Single object
    const log = extractLogFromObject(parsed)
    if (log) results.push(log)
    return results
  } catch {
    // Not a JSON array, try newline-delimited JSON
  }

  const lines = content.trim().split("\n")
  for (const line of lines) {
    try {
      const obj = JSON.parse(line.trim())
      const log = extractLogFromObject(obj)
      if (log) results.push(log)
    } catch {
      // Skip invalid lines
    }
  }

  return results
}

function extractLogFromObject(obj: Record<string, unknown>): ParsedLog | null {
  const message =
    (obj.message as string) ||
    (obj.msg as string) ||
    (obj.log as string) ||
    (obj.event as string) ||
    (obj.description as string)
  if (!message) return null

  const timestamp =
    (obj.timestamp as string) ||
    (obj.time as string) ||
    (obj.date as string) ||
    (obj["@timestamp"] as string) ||
    (obj.ts as string)

  const source =
    (obj.source as string) ||
    (obj.src as string) ||
    (obj.host as string) ||
    (obj.origin as string) ||
    "JSON-Import"

  const severityRaw =
    (obj.severity as string) ||
    (obj.level as string) ||
    (obj.priority as string)

  return {
    timestamp: timestamp ? tryParseTimestamp(timestamp) : undefined,
    source,
    message,
    severity: severityRaw ? mapSeverity(severityRaw) : detectSeverity(message),
  }
}

export function parsePlainTextLogs(content: string): ParsedLog[] {
  const lines = content.trim().split("\n")
  const results: ParsedLog[] = []

  // Common syslog pattern: <timestamp> <host> <message>
  const syslogRegex =
    /^(?:(<\d+>)\s*)?(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^ ]*)\s+(\S+)\s+(.+)$/

  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed) continue

    const match = trimmed.match(syslogRegex)
    if (match) {
      results.push({
        timestamp: tryParseTimestamp(match[2]),
        source: match[3],
        message: match[4],
        severity: detectSeverity(match[4]),
      })
    } else {
      results.push({
        source: "Text-Import",
        message: trimmed,
        severity: detectSeverity(trimmed),
      })
    }
  }

  return results
}

export function parseSyslogMessage(msg: string): ParsedLog {
  // RFC 3164: <PRI>TIMESTAMP HOSTNAME APP-NAME[PROCID]: MSG
  const rfc3164 =
    /^(?:<(\d+)>)?(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$/
  // RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
  const rfc5424 =
    /^(?:<(\d+)>)(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(?:\[.*?\]\s*)?(.*)$/

  let match = msg.match(rfc5424)
  if (match) {
    const pri = parseInt(match[1] || "13")
    return {
      timestamp: tryParseTimestamp(match[3]),
      source: `${match[4]}/${match[5]}`,
      message: match[8] || msg,
      severity: priToSeverity(pri),
    }
  }

  match = msg.match(rfc3164)
  if (match) {
    const pri = parseInt(match[1] || "13")
    return {
      timestamp: tryParseTimestamp(match[2]),
      source: `${match[3]}/${match[4]}`,
      message: match[6] || msg,
      severity: priToSeverity(pri),
    }
  }

  return {
    source: "Syslog",
    message: msg,
    severity: detectSeverity(msg),
  }
}

function priToSeverity(pri: number): Severity {
  const severity = pri & 0x07
  if (severity <= 1) return "critical"
  if (severity <= 3) return "high"
  if (severity <= 4) return "medium"
  if (severity <= 5) return "low"
  return "info"
}

export function detectFormat(content: string): "csv" | "json" | "text" {
  const trimmed = content.trim()
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) return "json"
  const firstLine = trimmed.split("\n")[0]
  if (firstLine.split(",").length >= 3) return "csv"
  return "text"
}

export function parseLogFile(content: string, format?: string): ParsedLog[] {
  const fmt = format || detectFormat(content)
  switch (fmt) {
    case "csv":
      return parseCSVLogs(content)
    case "json":
      return parseJSONLogs(content)
    default:
      return parsePlainTextLogs(content)
  }
}
