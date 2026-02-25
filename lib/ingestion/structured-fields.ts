export interface StructuredFieldsResult {
  fields: Record<string, unknown>
  confidence: number
  source: "json" | "kv" | "none"
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
  const regex = /([A-Za-z0-9_.-]+)=("([^"]*)"|'([^']*)'|[^\s]+)/g
  let match: RegExpExecArray | null
  while ((match = regex.exec(message)) !== null) {
    const key = match[1]
    const raw = match[3] ?? match[4] ?? match[2]
    fields[key] = raw
  }
  return fields
}

export function extractStructuredFields(message: string, parsedHint?: boolean): StructuredFieldsResult {
  const trimmed = message.trim()
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(trimmed)
      if (parsed && typeof parsed === "object") {
        const fields = flattenObject(Array.isArray(parsed) ? { items: parsed } : parsed as Record<string, unknown>)
        const confidence = parsedHint === false ? 70 : 90
        return { fields, confidence, source: "json" }
      }
    } catch {
      // Fall through to key=value parsing.
    }
  }

  const kvFields = extractKeyValuePairs(message)
  const kvCount = Object.keys(kvFields).length
  if (kvCount > 0) {
    let confidence = kvCount >= 4 ? 78 : kvCount >= 2 ? 68 : 55
    if (parsedHint === false) confidence -= 12
    return { fields: kvFields, confidence, source: "kv" }
  }

  return { fields: {}, confidence: parsedHint === false ? 35 : 45, source: "none" }
}
