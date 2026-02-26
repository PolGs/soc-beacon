import { getAlertById } from "@/lib/db/alerts"
import { upsertEnrichment } from "@/lib/db/enrichments"
import { collectThreatIntelForIndicators } from "./index"
import { extractIndicators } from "@/lib/indicators"
import { extractStructuredFields } from "@/lib/ingestion/structured-fields"
import { systemLog } from "@/lib/system-log"

const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/
const HASH_RE = /^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$/

export async function enrichAlertWithThreatIntel(alertId: string): Promise<void> {
  systemLog("info", "threat-intel", "Starting threat intel enrichment", { alertId })
  const alert = await getAlertById(alertId)
  if (!alert) throw new Error(`Alert ${alertId} not found`)

  const textBlob = [alert.title, alert.description, alert.rawLog, alert.sourceIp, alert.destIp]
    .filter(Boolean)
    .join("\n")

  const parsed = extractIndicators(textBlob)

  if (alert.sourceIp && alert.sourceIp !== "0.0.0.0") parsed.ips.unshift(alert.sourceIp)
  if (alert.destIp && alert.destIp !== "0.0.0.0") parsed.ips.push(alert.destIp)
  parsed.ips = [...new Set(parsed.ips)].slice(0, 12)

  // Also pull indicators from structured fields (persisted extraction first, parser fallback).
  try {
    const structuredFields =
      (alert.enrichment.extractedFields && Object.keys(alert.enrichment.extractedFields).length > 0)
        ? alert.enrichment.extractedFields
        : extractStructuredFields(alert.rawLog, true).fields

    for (const [key, value] of Object.entries(structuredFields)) {
      const k = key.toLowerCase()
      const v = String(value).trim()
      if (!v) continue
      // IP fields
      if (/(?:ip|addr|host|src|dst|source|dest|remote|client|server)/.test(k) && IPV4_RE.test(v)) {
        if (!parsed.ips.includes(v)) parsed.ips.push(v)
      }
      // Hash fields
      if (/(?:hash|md5|sha1|sha256|sha512|digest|checksum|file_hash)/.test(k) && HASH_RE.test(v)) {
        if (!parsed.hashes.includes(v)) parsed.hashes.push(v)
      }
      // URL fields
      if (/(?:url|uri|link|request|path|referer|referrer)/.test(k) && v.startsWith("http")) {
        if (!parsed.urls.includes(v)) parsed.urls.push(v)
      }
    }
    parsed.ips = [...new Set(parsed.ips)].slice(0, 12)
    parsed.hashes = [...new Set(parsed.hashes)].slice(0, 12)
    parsed.urls = [...new Set(parsed.urls)].slice(0, 8)
  } catch {
    // Structured field extraction is best-effort
  }

  const intel = await collectThreatIntelForIndicators(parsed)

  await upsertEnrichment(alertId, {
    threatIntel: intel.summary,
    threatIntelVendors: intel.vendors,
    ...(intel.geoCountry ? { geoCountry: intel.geoCountry } : {}),
    ...(intel.geoCity ? { geoCity: intel.geoCity } : {}),
    ...(intel.asnInfo ? { asnInfo: intel.asnInfo } : {}),
  })

  systemLog("info", "threat-intel", "Threat intel enrichment completed", {
    alertId,
    indicators: { ips: parsed.ips.length, hashes: parsed.hashes.length, urls: parsed.urls.length },
    vendorChecks: intel.vendors.length,
  })
}
