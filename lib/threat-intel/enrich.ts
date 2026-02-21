import { getAlertById } from "@/lib/db/alerts"
import { upsertEnrichment } from "@/lib/db/enrichments"
import { collectThreatIntelForIndicators } from "./index"
import { extractIndicators } from "@/lib/indicators"

export async function enrichAlertWithThreatIntel(alertId: string): Promise<void> {
  const alert = await getAlertById(alertId)
  if (!alert) throw new Error(`Alert ${alertId} not found`)

  const textBlob = [alert.title, alert.description, alert.rawLog, alert.sourceIp, alert.destIp]
    .filter(Boolean)
    .join("\n")

  const parsed = extractIndicators(textBlob)

  if (alert.sourceIp && alert.sourceIp !== "0.0.0.0") parsed.ips.unshift(alert.sourceIp)
  if (alert.destIp && alert.destIp !== "0.0.0.0") parsed.ips.push(alert.destIp)
  parsed.ips = [...new Set(parsed.ips)].slice(0, 12)

  const intel = await collectThreatIntelForIndicators(parsed)

  await upsertEnrichment(alertId, {
    threatIntel: intel.summary,
    ...(intel.geoCountry ? { geoCountry: intel.geoCountry } : {}),
    ...(intel.geoCity ? { geoCity: intel.geoCity } : {}),
    ...(intel.asnInfo ? { asnInfo: intel.asnInfo } : {}),
  })
}
