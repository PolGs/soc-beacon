import { systemLog } from "@/lib/system-log"

interface OTXResult {
  pulseCount: number
  reputation: number
  summary: string
}

export async function lookupIP(ip: string, apiKey: string): Promise<OTXResult | null> {
  try {
    const res = await fetch(
      `https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/general`,
      {
        headers: {
          "X-OTX-API-KEY": apiKey,
        },
      }
    )
    if (!res.ok) {
      systemLog("warn", "threat-intel", "AlienVault OTX IP lookup failed", { ip, status: res.status })
      return null
    }
    const data = await res.json()

    return {
      pulseCount: data.pulse_info?.count || 0,
      reputation: data.reputation || 0,
      summary: `OTX: ${data.pulse_info?.count || 0} threat pulses, reputation score: ${data.reputation || 0}`,
    }
  } catch (err) {
    systemLog("error", "threat-intel", "AlienVault OTX IP lookup error", { ip, error: String(err) })
    return null
  }
}

export async function lookupDomain(domain: string, apiKey: string): Promise<OTXResult | null> {
  try {
    const res = await fetch(
      `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/general`,
      {
        headers: {
          "X-OTX-API-KEY": apiKey,
        },
      }
    )
    if (!res.ok) {
      systemLog("warn", "threat-intel", "AlienVault OTX domain lookup failed", { domain, status: res.status })
      return null
    }
    const data = await res.json()

    return {
      pulseCount: data.pulse_info?.count || 0,
      reputation: data.reputation || 0,
      summary: `OTX: ${data.pulse_info?.count || 0} threat pulses`,
    }
  } catch (err) {
    systemLog("error", "threat-intel", "AlienVault OTX domain lookup error", { domain, error: String(err) })
    return null
  }
}
