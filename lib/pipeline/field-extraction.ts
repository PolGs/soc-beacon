import { getSetting } from "@/lib/db/settings"
import { getLLMClient } from "@/lib/llm"
import { extractStructuredFields } from "@/lib/ingestion/structured-fields"

const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/
const DOMAIN_RE = /^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}$/
const PORT_RE = /^([1-9]\d{0,4})$/
const URL_RE = /^https?:\/\/[^\s]+$/i
const HASH_RE = /^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$/

type MappedFieldKey =
  | "source"
  | "sourceIp"
  | "destIp"
  | "sourcePort"
  | "destPort"
  | "user"
  | "hostname"
  | "domain"
  | "url"
  | "proto"
  | "eventId"
  | "action"
  | "result"
  | "filePath"
  | "hash"

export type MappedFields = {
  source?: string
  sourceIp: string
  destIp: string
  sourcePort?: string
  destPort?: string
  user?: string
  hostname?: string
  domain?: string
  url?: string
  proto?: string
  eventId?: string
  action?: string
  result?: string
  filePath?: string
  hash?: string
}

type FieldConfidence = Partial<Record<MappedFieldKey, number>>

export interface EarlyFieldExtractionResult {
  fields: Record<string, unknown>
  confidence: number
  source: "heuristic" | "ai" | "hybrid"
  mapped: MappedFields
  fieldConfidence: FieldConfidence
  fieldConfidenceThreshold: number
}

function clampConfidence(value: unknown, fallback = 0): number {
  if (typeof value !== "number" || Number.isNaN(value)) return fallback
  return Math.max(0, Math.min(100, Math.round(value)))
}

function normalizeValue(v: unknown): string | undefined {
  if (v === null || v === undefined) return undefined
  const s = String(v).trim()
  return s ? s : undefined
}

function getFirstNonEmpty(fields: Record<string, unknown>, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = normalizeValue(fields[key])
    if (value) return value
  }
  return undefined
}

function toFieldRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {}
  return value as Record<string, unknown>
}

function parseJsonObject(raw: string): Record<string, unknown> | null {
  try {
    const match = raw.match(/\{[\s\S]*\}/)
    const parsed = JSON.parse(match ? match[0] : raw)
    return toFieldRecord(parsed)
  } catch {
    return null
  }
}

function isValidIpv4(value: string | undefined): value is string {
  return !!value && IPV4_RE.test(value)
}

function isValidPort(value: string | undefined): boolean {
  if (!value || !PORT_RE.test(value)) return false
  const parsed = Number(value)
  return parsed >= 1 && parsed <= 65535
}

function trimHugeFieldSet(fields: Record<string, unknown>, max = 180): Record<string, unknown> {
  const entries = Object.entries(fields)
  if (entries.length <= max) return fields
  return Object.fromEntries(entries.slice(0, max))
}

function scoreByValidation(key: MappedFieldKey, value: string | undefined): number {
  if (!value) return 0
  switch (key) {
    case "sourceIp":
    case "destIp":
      return isValidIpv4(value) ? 100 : 0
    case "sourcePort":
    case "destPort":
      return isValidPort(value) ? 94 : 0
    case "domain":
      return DOMAIN_RE.test(value.toLowerCase()) ? 88 : 35
    case "url":
      return URL_RE.test(value) ? 90 : 30
    case "hash":
      return HASH_RE.test(value) ? 96 : 25
    case "eventId":
      return /^\d+$/.test(value) ? 86 : 60
    case "filePath":
      return /[\\/]/.test(value) ? 82 : 50
    case "proto":
      return /^(tcp|udp|icmp|http|https|ssh|dns|smtp|imap|pop3|tls)$/i.test(value) ? 84 : 58
    default:
      return 70
  }
}

function mapHeuristicFields(fields: Record<string, unknown>, message: string, seedSource?: string): {
  mapped: MappedFields
  fieldConfidence: FieldConfidence
} {
  const allIps = message.match(/\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g) || []

  const sourceIp =
    getFirstNonEmpty(fields, [
      "src_ip", "source_ip", "source.ip", "src", "sip", "client_ip", "srcIp", "sourceAddress",
      "srcip", "ip.src", "source", "syslog.source_ip",
    ]) ||
    allIps[0] ||
    "0.0.0.0"

  const destIp =
    getFirstNonEmpty(fields, [
      "dst_ip", "dest_ip", "destination_ip", "destination.ip", "dst", "dip", "server_ip", "destIp",
      "destinationAddress", "dstip", "ip.dst", "target_ip", "to",
    ]) ||
    allIps[1] ||
    "0.0.0.0"

  const mapped: MappedFields = {
    source: getFirstNonEmpty(fields, [
      "source", "host", "hostname", "device", "device.product", "syslog.hostname", "syslog.appname",
    ]) || seedSource,
    sourceIp: isValidIpv4(sourceIp) ? sourceIp : "0.0.0.0",
    destIp: isValidIpv4(destIp) ? destIp : "0.0.0.0",
    sourcePort: getFirstNonEmpty(fields, ["src_port", "source_port", "sport", "spt", "sourcePort"]),
    destPort: getFirstNonEmpty(fields, ["dst_port", "dest_port", "dport", "dpt", "destinationPort"]),
    user: getFirstNonEmpty(fields, ["user", "username", "acct", "account", "principal"]),
    hostname: getFirstNonEmpty(fields, ["hostname", "host", "computer", "device", "syslog.hostname"]),
    domain: getFirstNonEmpty(fields, ["domain", "dns", "fqdn", "realm"]),
    url: getFirstNonEmpty(fields, ["url", "uri", "request", "path"]),
    proto: getFirstNonEmpty(fields, ["proto", "protocol", "transport"]),
    eventId: getFirstNonEmpty(fields, ["event_id", "EventID", "event.id", "signature.id"]),
    action: getFirstNonEmpty(fields, ["action", "act", "operation"]),
    result: getFirstNonEmpty(fields, ["result", "status", "outcome", "disposition"]),
    filePath: getFirstNonEmpty(fields, ["file_path", "file", "path", "image", "process.path"]),
    hash: getFirstNonEmpty(fields, ["hash_sha256", "sha256", "hash_sha1", "sha1", "hash_md5", "md5", "hash"]),
  }

  const fieldConfidence: FieldConfidence = {}
  const keys: MappedFieldKey[] = [
    "source", "sourceIp", "destIp", "sourcePort", "destPort", "user", "hostname", "domain",
    "url", "proto", "eventId", "action", "result", "filePath", "hash",
  ]
  for (const key of keys) {
    const value = mapped[key]
    if (!value) continue
    fieldConfidence[key] = scoreByValidation(key, value)
  }

  return { mapped, fieldConfidence }
}

async function extractWithAI(message: string, baseFields: Record<string, unknown>, seedSource?: string): Promise<{
  fields: Record<string, unknown>
  mapped: Partial<MappedFields>
  confidence: number
  fieldConfidence: FieldConfidence
} | null> {
  const llm = await getSetting<{ provider?: string; apiKey?: string }>("llm", {})
  const apiKey = (llm.apiKey || "").trim()
  if (!apiKey || !llm.provider || llm.provider === "local") return null

  const client = await getLLMClient()
  const system = `Extract structured cybersecurity log fields.
Return ONLY valid JSON:
{
  "fields": { "key": "value" },
  "mapped": {
    "source": "string",
    "sourceIp": "x.x.x.x",
    "destIp": "x.x.x.x",
    "sourcePort": "string",
    "destPort": "string",
    "user": "string",
    "hostname": "string",
    "domain": "string",
    "url": "string",
    "proto": "string",
    "eventId": "string",
    "action": "string",
    "result": "string",
    "filePath": "string",
    "hash": "string"
  },
  "fieldConfidence": {
    "source": 0-100,
    "sourceIp": 0-100,
    "destIp": 0-100,
    "sourcePort": 0-100,
    "destPort": 0-100,
    "user": 0-100,
    "hostname": 0-100,
    "domain": 0-100,
    "url": 0-100,
    "proto": 0-100,
    "eventId": 0-100,
    "action": 0-100,
    "result": 0-100,
    "filePath": 0-100,
    "hash": 0-100
  },
  "confidence": 0-100
}
Rules:
- Do not invent values.
- Omit unknown fields.
- fieldConfidence must be conservative.`

  const user = `Seed source: ${seedSource || "unknown"}
Seed extracted fields (heuristic):
${JSON.stringify(baseFields)}

Raw log:
${message.slice(0, 2400)}`

  const response = await client.chat([
    { role: "system", content: system },
    { role: "user", content: user },
  ])

  const parsed = parseJsonObject(response.content)
  if (!parsed) return null

  const fields = trimHugeFieldSet(toFieldRecord(parsed.fields))
  const mappedRaw = toFieldRecord(parsed.mapped)
  const mapped: Partial<MappedFields> = {
    source: normalizeValue(mappedRaw.source),
    sourceIp: normalizeValue(mappedRaw.sourceIp),
    destIp: normalizeValue(mappedRaw.destIp),
    sourcePort: normalizeValue(mappedRaw.sourcePort),
    destPort: normalizeValue(mappedRaw.destPort),
    user: normalizeValue(mappedRaw.user),
    hostname: normalizeValue(mappedRaw.hostname),
    domain: normalizeValue(mappedRaw.domain),
    url: normalizeValue(mappedRaw.url),
    proto: normalizeValue(mappedRaw.proto),
    eventId: normalizeValue(mappedRaw.eventId),
    action: normalizeValue(mappedRaw.action),
    result: normalizeValue(mappedRaw.result),
    filePath: normalizeValue(mappedRaw.filePath),
    hash: normalizeValue(mappedRaw.hash),
  }

  const fieldConfidence: FieldConfidence = {}
  const fcRaw = toFieldRecord(parsed.fieldConfidence)
  const keys: MappedFieldKey[] = [
    "source", "sourceIp", "destIp", "sourcePort", "destPort", "user", "hostname", "domain",
    "url", "proto", "eventId", "action", "result", "filePath", "hash",
  ]
  for (const key of keys) {
    if (fcRaw[key] === undefined) continue
    fieldConfidence[key] = clampConfidence(fcRaw[key], 0)
  }

  return {
    fields,
    mapped,
    confidence: clampConfidence(parsed.confidence, 0),
    fieldConfidence,
  }
}

function mergeFieldConfidence(
  heuristic: FieldConfidence,
  ai: FieldConfidence | null,
  baseConfidence: number
): FieldConfidence {
  const merged: FieldConfidence = {}
  const keys: MappedFieldKey[] = [
    "source", "sourceIp", "destIp", "sourcePort", "destPort", "user", "hostname", "domain",
    "url", "proto", "eventId", "action", "result", "filePath", "hash",
  ]

  for (const key of keys) {
    const h = clampConfidence(heuristic[key], 0)
    const a = ai ? clampConfidence(ai[key], -1) : -1
    const combined = a >= 0 ? Math.round((h * 0.4) + (a * 0.6)) : h
    merged[key] = Math.max(0, Math.min(100, Math.round((combined * 0.85) + (baseConfidence * 0.15))))
  }

  return merged
}

function applyConfidenceGating(mapped: MappedFields, fieldConfidence: FieldConfidence, threshold: number): MappedFields {
  const gated: MappedFields = {
    sourceIp: mapped.sourceIp,
    destIp: mapped.destIp,
  }

  const setIfQualified = (key: MappedFieldKey, value: string | undefined) => {
    if (!value) return
    const conf = clampConfidence(fieldConfidence[key], 0)
    if (conf >= threshold) {
      ;(gated as Record<string, string>)[key] = value
    }
  }

  // Keep source/destination IP defaults safe even if confidence is low.
  gated.sourceIp = isValidIpv4(mapped.sourceIp) ? mapped.sourceIp : "0.0.0.0"
  gated.destIp = isValidIpv4(mapped.destIp) ? mapped.destIp : "0.0.0.0"

  setIfQualified("source", mapped.source)
  setIfQualified("sourcePort", mapped.sourcePort)
  setIfQualified("destPort", mapped.destPort)
  setIfQualified("user", mapped.user)
  setIfQualified("hostname", mapped.hostname)
  setIfQualified("domain", mapped.domain)
  setIfQualified("url", mapped.url)
  setIfQualified("proto", mapped.proto)
  setIfQualified("eventId", mapped.eventId)
  setIfQualified("action", mapped.action)
  setIfQualified("result", mapped.result)
  setIfQualified("filePath", mapped.filePath)
  setIfQualified("hash", mapped.hash)

  return gated
}

export async function extractAndMapLogFields(
  message: string,
  parsedHint?: boolean,
  seedSource?: string
): Promise<EarlyFieldExtractionResult> {
  const pipelineSettings = await getSetting<{ fieldConfidenceThreshold?: number }>("pipeline", {})
  const fieldConfidenceThreshold = Math.max(0, Math.min(100, pipelineSettings.fieldConfidenceThreshold ?? 60))

  const base = extractStructuredFields(message, parsedHint)
  const heuristic = mapHeuristicFields(base.fields, message, seedSource)

  try {
    const ai = await extractWithAI(message, base.fields, seedSource)
    if (!ai) {
      const mergedFieldConfidence = mergeFieldConfidence(
        heuristic.fieldConfidence,
        null,
        clampConfidence(base.confidence, 45)
      )
      return {
        fields: trimHugeFieldSet(base.fields),
        confidence: clampConfidence(base.confidence, 45),
        source: "heuristic",
        mapped: applyConfidenceGating(heuristic.mapped, mergedFieldConfidence, fieldConfidenceThreshold),
        fieldConfidence: mergedFieldConfidence,
        fieldConfidenceThreshold,
      }
    }

    const mergedFields = trimHugeFieldSet({ ...base.fields, ...ai.fields })
    const mergedMapped: MappedFields = {
      ...heuristic.mapped,
      ...ai.mapped,
      sourceIp: isValidIpv4(ai.mapped.sourceIp) ? ai.mapped.sourceIp : heuristic.mapped.sourceIp,
      destIp: isValidIpv4(ai.mapped.destIp) ? ai.mapped.destIp : heuristic.mapped.destIp,
    }

    const confidence = clampConfidence(
      Math.round((clampConfidence(base.confidence, 45) * 0.45) + (clampConfidence(ai.confidence, 0) * 0.55)),
      clampConfidence(base.confidence, 45)
    )

    const mergedFieldConfidence = mergeFieldConfidence(
      heuristic.fieldConfidence,
      ai.fieldConfidence,
      confidence
    )

    return {
      fields: mergedFields,
      confidence,
      source: Object.keys(ai.fields).length > 0 ? "hybrid" : "heuristic",
      mapped: applyConfidenceGating(mergedMapped, mergedFieldConfidence, fieldConfidenceThreshold),
      fieldConfidence: mergedFieldConfidence,
      fieldConfidenceThreshold,
    }
  } catch {
    const mergedFieldConfidence = mergeFieldConfidence(
      heuristic.fieldConfidence,
      null,
      clampConfidence(base.confidence, 45)
    )
    return {
      fields: trimHugeFieldSet(base.fields),
      confidence: clampConfidence(base.confidence, 45),
      source: "heuristic",
      mapped: applyConfidenceGating(heuristic.mapped, mergedFieldConfidence, fieldConfidenceThreshold),
      fieldConfidence: mergedFieldConfidence,
      fieldConfidenceThreshold,
    }
  }
}
