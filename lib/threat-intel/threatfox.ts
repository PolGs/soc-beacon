import { systemLog } from "@/lib/system-log"

interface ThreatFoxSummary {
  summary: string
}

type ThreatFoxQueryType = "search_ioc" | "search_hash"

async function queryThreatFox(
  query: ThreatFoxQueryType,
  searchTerm: string
): Promise<Record<string, unknown>[] | null> {
  try {
    const res = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query,
        search_term: searchTerm,
      }),
    })
    if (!res.ok) {
      systemLog("warn", "threat-intel", "ThreatFox request failed", { query, status: res.status })
      return null
    }

    const data = (await res.json()) as {
      query_status?: string
      data?: Array<Record<string, unknown>>
    }

    if (data.query_status !== "ok" || !Array.isArray(data.data)) return null
    return data.data
  } catch (err) {
    systemLog("error", "threat-intel", "ThreatFox request error", { query, error: String(err) })
    return null
  }
}

function buildSummary(prefix: string, records: Record<string, unknown>[]): ThreatFoxSummary {
  const first = records[0] || {}
  const malware = String(first.malware || "unknown")
  const iocType = String(first.ioc_type || "unknown")
  const confidence = String(first.confidence_level || "n/a")
  return {
    summary: `ThreatFox: ${prefix} hit (${records.length} records, type=${iocType}, malware=${malware}, confidence=${confidence})`,
  }
}

export async function lookupIP(ip: string): Promise<ThreatFoxSummary | null> {
  const records = await queryThreatFox("search_ioc", ip)
  if (!records || records.length === 0) return null
  return buildSummary(`IP ${ip}`, records)
}

export async function lookupDomain(domain: string): Promise<ThreatFoxSummary | null> {
  const records = await queryThreatFox("search_ioc", domain)
  if (!records || records.length === 0) return null
  return buildSummary(`domain ${domain}`, records)
}

export async function lookupUrl(url: string): Promise<ThreatFoxSummary | null> {
  const records = await queryThreatFox("search_ioc", url)
  if (!records || records.length === 0) return null
  return buildSummary("URL", records)
}

export async function lookupHash(hash: string): Promise<ThreatFoxSummary | null> {
  const records = await queryThreatFox("search_hash", hash)
  if (!records || records.length === 0) return null
  return buildSummary("hash", records)
}
