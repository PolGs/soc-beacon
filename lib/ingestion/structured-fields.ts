export interface StructuredFieldsResult {
  fields: Record<string, unknown>
  confidence: number
  source: "json" | "kv" | "cef" | "leef" | "syslog" | "none"
}

function flattenObject(obj: Record<string, unknown>, prefix = "", out: Record<string, unknown> = {}) {
  for (const [key, value] of Object.entries(obj)) {
    const nextKey = prefix ? `${prefix}.${key}` : key
    if (value && typeof value === "object" && !Array.isArray(value)) {
      flattenObject(value as Record<string, unknown>, nextKey, out)
    } else {
      out[nextKey] = value
    }
  }
  return out
}

function extractKeyValuePairs(message: string): Record<string, unknown> {
  const fields: Record<string, unknown> = {}
  // Match key=value pairs, supporting quoted values and various separators
  const regex = /([A-Za-z0-9_.\-]+)\s*=\s*("([^"]*)"|'([^']*)'|[^\s,;|]+)/g
  let match: RegExpExecArray | null
  while ((match = regex.exec(message)) !== null) {
    const key = match[1]
    // Skip obvious non-fields like URLs and IPs
    if (key.length > 64 || /^(http|ftp)s?$/.test(key)) continue
    const raw = match[3] ?? match[4] ?? match[2]
    fields[key] = raw
  }
  return fields
}

/** Parse CEF (Common Event Format): CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension */
function parseCEF(message: string): Record<string, unknown> | null {
  const cefMatch = message.match(/^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$/i)
  if (!cefMatch) return null
  const fields: Record<string, unknown> = {
    "cef.version": cefMatch[1],
    "device.vendor": cefMatch[2],
    "device.product": cefMatch[3],
    "device.version": cefMatch[4],
    "signature.id": cefMatch[5],
    "event.name": cefMatch[6],
    "event.severity": cefMatch[7],
  }
  // Parse extension key=value pairs
  const ext = cefMatch[8]
  const extRegex = /([A-Za-z0-9_]+)=((?:[^\\=\s]|\\.)+(?:\s(?![A-Za-z0-9_]+=)(?:[^\\=\s]|\\.)+)*)/g
  let m: RegExpExecArray | null
  while ((m = extRegex.exec(ext)) !== null) {
    fields[m[1]] = m[2].trim()
  }
  return fields
}

/** Parse LEEF (Log Event Extended Format): LEEF:Version|Vendor|Product|Version|EventID|... */
function parseLEEF(message: string): Record<string, unknown> | null {
  const leefMatch = message.match(/^LEEF:(\d+(?:\.\d+)?)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|^t]*)([\t|](.*))?$/)
  if (!leefMatch) return null
  const fields: Record<string, unknown> = {
    "leef.version": leefMatch[1],
    "device.vendor": leefMatch[2],
    "device.product": leefMatch[3],
    "device.version": leefMatch[4],
    "event.id": leefMatch[5],
  }
  const attrStr = leefMatch[7] || ""
  const sep = leefMatch[6]?.startsWith("\t") ? "\t" : "|"
  const pairs = attrStr.split(sep === "\t" ? "\t" : /\t|\|/)
  for (const pair of pairs) {
    const eqIdx = pair.indexOf("=")
    if (eqIdx > 0) {
      fields[pair.slice(0, eqIdx).trim()] = pair.slice(eqIdx + 1).trim()
    }
  }
  return fields
}

/** Parse RFC 3164 / RFC 5424 syslog */
function parseSyslog(message: string): Record<string, unknown> | null {
  // RFC 5424: <priority>version timestamp hostname app-name procid msgid [structured-data] msg
  const rfc5424 = message.match(
    /^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\[.*?\])?\s*(.*)$/
  )
  if (rfc5424) {
    const pri = parseInt(rfc5424[1], 10)
    const fields: Record<string, unknown> = {
      "syslog.facility": Math.floor(pri / 8),
      "syslog.severity": pri % 8,
      "syslog.version": rfc5424[2],
      "syslog.timestamp": rfc5424[3],
      "syslog.hostname": rfc5424[4],
      "syslog.appname": rfc5424[5],
      "syslog.procid": rfc5424[6],
      "syslog.msgid": rfc5424[7],
      "syslog.message": rfc5424[9],
    }
    // Parse structured data elements like [exampleSDID@32473 iut="3" eventSource="Application"]
    const sd = rfc5424[8]
    if (sd && sd !== "-") {
      const sdRegex = /\[([^\s\]]+)([^\]]*)\]/g
      let sdm: RegExpExecArray | null
      while ((sdm = sdRegex.exec(sd)) !== null) {
        const sdId = sdm[1]
        const kvPart = sdm[2]
        const kvRegex = /([A-Za-z0-9_]+)="([^"]*)"/g
        let kv: RegExpExecArray | null
        while ((kv = kvRegex.exec(kvPart)) !== null) {
          fields[`sd.${sdId}.${kv[1]}`] = kv[2]
        }
      }
    }
    return fields
  }

  // RFC 3164: <priority>Month DD HH:MM:SS hostname tag: message
  const rfc3164 = message.match(
    /^<(\d+)>(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([A-Za-z0-9_/-]+(?:\[\d+\])?):?\s*(.*)$/
  )
  if (rfc3164) {
    const pri = parseInt(rfc3164[1], 10)
    return {
      "syslog.facility": Math.floor(pri / 8),
      "syslog.severity": pri % 8,
      "syslog.timestamp": rfc3164[2],
      "syslog.hostname": rfc3164[3],
      "syslog.appname": rfc3164[4].replace(/\[\d+\]$/, ""),
      "syslog.message": rfc3164[5],
    }
  }

  // Bare syslog without priority bracket
  const bare = message.match(
    /^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+(\S+)\s+([A-Za-z0-9_/-]+(?:\[\d+\])?):?\s*(.*)$/
  )
  if (bare) {
    return {
      "syslog.timestamp": bare[1],
      "syslog.hostname": bare[2],
      "syslog.appname": bare[3].replace(/\[\d+\]$/, ""),
      "syslog.message": bare[4],
    }
  }

  return null
}

/** Extract common security fields using named patterns */
function extractNamedPatterns(message: string): Record<string, unknown> {
  const fields: Record<string, unknown> = {}

  const patterns: Array<{ key: string; regex: RegExp }> = [
    { key: "src_ip", regex: /(?:src(?:_ip)?|source(?:_ip)?|from)[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})/i },
    { key: "dst_ip", regex: /(?:dst(?:_ip)?|dest(?:_ip)?|destination(?:_ip)?|to)[=:\s]+(\d{1,3}(?:\.\d{1,3}){3})/i },
    { key: "src_port", regex: /(?:src(?:_port)?|sport)[=:\s]+(\d{2,5})/i },
    { key: "dst_port", regex: /(?:dst(?:_port)?|dport|dest(?:_port)?)[=:\s]+(\d{2,5})/i },
    { key: "user", regex: /(?:user(?:name)?|acct|account)[=:\s]+["']?([A-Za-z0-9_\\.\-@]+)["']?/i },
    { key: "process", regex: /(?:proc(?:ess)?|cmd|command|exe(?:cutable)?)[=:\s]+["']?([A-Za-z0-9_\-./\\]+(?:\.[a-z]{1,4})?)["']?/i },
    { key: "action", regex: /(?:action|act)[=:\s]+["']?([A-Za-z_\-]+)["']?/i },
    { key: "result", regex: /(?:result|outcome|status)[=:\s]+["']?([A-Za-z_\-]+)["']?/i },
    { key: "proto", regex: /(?:proto(?:col)?)[=:\s]+["']?([A-Za-z0-9]+)["']?/i },
    { key: "bytes", regex: /(?:bytes?|size|len(?:gth)?)[=:\s]+(\d+)/i },
    { key: "event_id", regex: /(?:event[_.]?id|eid|evtid)[=:\s]+["']?(\d+)["']?/i },
    { key: "severity_field", regex: /(?:severity|level|priority)[=:\s]+["']?([A-Za-z0-9]+)["']?/i },
    { key: "domain", regex: /(?:domain|workgroup|realm)[=:\s]+["']?([A-Za-z0-9_\-\.]+)["']?/i },
    { key: "url", regex: /(?:url|uri|path|request)[=:\s]+["']?(https?:\/\/[^\s"']+|\/[^\s"']+)["']?/i },
    { key: "hash_md5", regex: /(?:md5|hash)[=:\s]+["']?([A-Fa-f0-9]{32})["']?/i },
    { key: "hash_sha1", regex: /(?:sha1)[=:\s]+["']?([A-Fa-f0-9]{40})["']?/i },
    { key: "hash_sha256", regex: /(?:sha256|sha2)[=:\s]+["']?([A-Fa-f0-9]{64})["']?/i },
    { key: "hostname", regex: /(?:host(?:name)?|computer|machine|device)[=:\s]+["']?([A-Za-z0-9_\-\.]+)["']?/i },
    { key: "file_path", regex: /(?:file(?:path|name)?|path|image)[=:\s]+["']?([A-Za-z]:[\\/][^\s"']+|\/[^\s"']+)["']?/i },
    { key: "pid", regex: /(?:pid|process_id)[=:\s]+(\d+)/i },
  ]

  for (const { key, regex } of patterns) {
    const m = message.match(regex)
    if (m && m[1] && !(key in fields)) {
      fields[key] = m[1]
    }
  }

  return fields
}

export function extractStructuredFields(message: string, parsedHint?: boolean): StructuredFieldsResult {
  const trimmed = message.trim()

  // 1. Try JSON
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(trimmed)
      if (parsed && typeof parsed === "object") {
        const fields = flattenObject(Array.isArray(parsed) ? { items: parsed } : parsed as Record<string, unknown>)
        const confidence = parsedHint === false ? 70 : 90
        return { fields, confidence, source: "json" }
      }
    } catch {
      // Fall through
    }
  }

  // 2. Try CEF
  const cefFields = parseCEF(trimmed)
  if (cefFields) {
    return { fields: cefFields, confidence: 92, source: "cef" }
  }

  // 3. Try LEEF
  const leefFields = parseLEEF(trimmed)
  if (leefFields) {
    return { fields: leefFields, confidence: 90, source: "leef" }
  }

  // 4. Try syslog
  const syslogFields = parseSyslog(trimmed)
  if (syslogFields) {
    // Also extract KV pairs from the syslog message field if present
    const msgField = (syslogFields["syslog.message"] as string) || ""
    const innerKv = extractKeyValuePairs(msgField)
    const combined = { ...syslogFields, ...innerKv }
    const confidence = parsedHint === false ? 70 : 85
    return { fields: combined, confidence, source: "syslog" }
  }

  // 5. Try key=value extraction
  const kvFields = extractKeyValuePairs(trimmed)
  const kvCount = Object.keys(kvFields).length

  // 6. Also run named pattern extraction and merge
  const namedFields = extractNamedPatterns(trimmed)
  const merged = { ...kvFields, ...namedFields }
  const mergedCount = Object.keys(merged).length

  if (mergedCount > 0) {
    let confidence = mergedCount >= 6 ? 78 : mergedCount >= 3 ? 68 : kvCount > 0 ? 55 : 40
    if (parsedHint === false) confidence -= 12
    return { fields: merged, confidence: Math.max(0, confidence), source: "kv" }
  }

  return { fields: {}, confidence: parsedHint === false ? 35 : 45, source: "none" }
}

/** Returns only the most relevant display fields for the UI header, deduplicated and filtered */
export function getDisplayFields(fields: Record<string, unknown>): Array<{ key: string; value: string }> {
  // Priority keys to show first
  const priorityKeys = [
    "user", "username", "acct",
    "src_ip", "sourceAddress", "src", "sip",
    "dst_ip", "destinationAddress", "dst", "dip",
    "src_port", "sourcePort", "spt",
    "dst_port", "destinationPort", "dpt",
    "hostname", "host", "computer", "machine",
    "process", "proc", "exe", "image",
    "action", "act",
    "result", "outcome",
    "proto", "protocol",
    "event_id", "EventID", "signature.id", "event.id",
    "file_path", "filePath", "fileName",
    "url", "uri",
    "bytes", "bytesIn", "in", "out",
    "pid",
    "domain",
    "hash_md5", "hash_sha1", "hash_sha256",
    "device.product", "device.vendor",
    "event.name", "event.severity",
    "syslog.appname", "syslog.hostname",
  ]

  const seen = new Set<string>()
  const result: Array<{ key: string; value: string }> = []

  // Emit priority keys first
  for (const pk of priorityKeys) {
    if (pk in fields && !seen.has(pk)) {
      const val = fields[pk]
      if (val !== null && val !== undefined && val !== "" && val !== "0.0.0.0" && val !== "-") {
        seen.add(pk)
        result.push({ key: formatFieldKey(pk), value: String(val) })
        if (result.length >= 12) break
      }
    }
  }

  // Then fill remaining slots with other fields (skip long values, timestamps)
  if (result.length < 12) {
    for (const [key, val] of Object.entries(fields)) {
      if (seen.has(key)) continue
      if (val === null || val === undefined || val === "" || val === "-") continue
      const strVal = String(val)
      if (strVal.length > 120) continue
      // Skip timestamp-like fields
      if (/time|date|ts$|_at$|timestamp/i.test(key)) continue
      seen.add(key)
      result.push({ key: formatFieldKey(key), value: strVal })
      if (result.length >= 12) break
    }
  }

  return result
}

function formatFieldKey(key: string): string {
  // Convert snake_case and dot.notation to Title Case
  return key
    .replace(/^(syslog|sd|cef|leef|device|event)\./i, "")
    .replace(/[_.-]+/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .replace(/\bIp\b/g, "IP")
    .replace(/\bId\b/g, "ID")
    .replace(/\bUrl\b/g, "URL")
    .replace(/\bMd5\b/g, "MD5")
    .replace(/\bSha\b/g, "SHA")
    .replace(/\bDst\b/g, "Dst")
    .replace(/\bSrc\b/g, "Src")
    .trim()
}
