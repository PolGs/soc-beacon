import { getThreatFeeds } from "@/lib/db/threat-feeds"
import * as virustotal from "./virustotal"
import * as abuseipdb from "./abuseipdb"
import * as alienvault from "./alienvault"
import * as geoip from "./geoip"
import * as urlhaus from "./urlhaus"
import * as googleSafeBrowsing from "./google-safe-browsing"
import * as threatfox from "./threatfox"
import * as spamhausDrop from "./spamhaus-drop"
import type { ExtractedIndicators } from "@/lib/indicators"
import { systemLog } from "@/lib/system-log"

interface ThreatIntelResult {
  threatIntel: string
  geoCountry: string | null
  geoCity: string | null
  asnInfo: string | null
}

export interface ThreatIntelSnapshot {
  summary: string
  geoCountry: string | null
  geoCity: string | null
  asnInfo: string | null
}

function findFeedApiKey(feeds: Array<{ name: string; apiKey: string; enabled: boolean }>, pattern: RegExp): string | null {
  const feed = feeds.find((f) => f.enabled && pattern.test(f.name.toLowerCase()) && f.apiKey)
  return feed?.apiKey || null
}

export async function lookupIP(ip: string): Promise<ThreatIntelResult> {
  const feeds = await getThreatFeeds()
  const results: string[] = []

  // VirusTotal
  const vtKey = findFeedApiKey(feeds, /virus\s*total|vt/)
  if (vtKey) {
    const vt = await virustotal.lookupIP(ip, vtKey)
    if (vt) results.push(vt.summary)
  }

  // AbuseIPDB
  const abuseKey = findFeedApiKey(feeds, /abuse\s*ip|abuseipdb/)
  if (abuseKey) {
    const abuse = await abuseipdb.checkIP(ip, abuseKey)
    if (abuse) results.push(abuse.summary)
  }

  // AlienVault OTX
  const otxKey = findFeedApiKey(feeds, /alien\s*vault|otx/)
  if (otxKey) {
    const otx = await alienvault.lookupIP(ip, otxKey)
    if (otx) results.push(otx.summary)
  }

  // GeoIP (free, no key needed)
  const geo = await geoip.lookupIP(ip)
  const tf = await threatfox.lookupIP(ip)
  if (tf) results.push(tf.summary)
  const drop = await spamhausDrop.lookupIP(ip)
  if (drop) results.push(drop.summary)

  return {
    threatIntel: results.length > 0 ? results.join(". ") : "No threat intelligence data available for this IP.",
    geoCountry: geo?.country || null,
    geoCity: geo?.city || null,
    asnInfo: geo ? `${geo.asn} - ${geo.isp}` : null,
  }
}

export async function collectThreatIntelForIndicators(indicators: ExtractedIndicators): Promise<ThreatIntelSnapshot> {
  systemLog("info", "threat-intel", "Collecting indicators", {
    ips: indicators.ips.length,
    urls: indicators.urls.length,
    domains: indicators.domains.length,
    hashes: indicators.hashes.length,
  })
  const feeds = await getThreatFeeds()
  const summaries: string[] = []

  let geoCountry: string | null = null
  let geoCity: string | null = null
  let asnInfo: string | null = null

  const vtKey = findFeedApiKey(feeds, /virus\s*total|vt/)
  const abuseKey = findFeedApiKey(feeds, /abuse\s*ip|abuseipdb/)
  const otxKey = findFeedApiKey(feeds, /alien\s*vault|otx/)
  const gsbKey = findFeedApiKey(feeds, /google|safe\s*browsing/)

  for (const ip of indicators.ips.slice(0, 3)) {
    const ipSummaries: string[] = []

    if (vtKey) {
      const vt = await virustotal.lookupIP(ip, vtKey)
      if (vt) ipSummaries.push(vt.summary)
    }
    if (abuseKey) {
      const abuse = await abuseipdb.checkIP(ip, abuseKey)
      if (abuse) ipSummaries.push(abuse.summary)
    }
    if (otxKey) {
      const otx = await alienvault.lookupIP(ip, otxKey)
      if (otx) ipSummaries.push(otx.summary)
    }
    const tf = await threatfox.lookupIP(ip)
    if (tf) ipSummaries.push(tf.summary)
    const drop = await spamhausDrop.lookupIP(ip)
    if (drop) ipSummaries.push(drop.summary)

    const geo = await geoip.lookupIP(ip)
    if (geo && !geoCountry) {
      geoCountry = geo.country || null
      geoCity = geo.city || null
      asnInfo = geo.asn && geo.isp ? `${geo.asn} - ${geo.isp}` : geo.asn || null
    }

    if (ipSummaries.length > 0) {
      summaries.push(`IP ${ip}: ${ipSummaries.join(" | ")}`)
    }
  }

  for (const domain of indicators.domains.slice(0, 3)) {
    const domainSummaries: string[] = []
    if (vtKey) {
      const vt = await virustotal.lookupDomain(domain, vtKey)
      if (vt) domainSummaries.push(vt.summary)
    }
    if (otxKey) {
      const otx = await alienvault.lookupDomain(domain, otxKey)
      if (otx) domainSummaries.push(otx.summary)
    }

    const uh = await urlhaus.lookupHost(domain)
    if (uh) domainSummaries.push(uh.summary)
    const tf = await threatfox.lookupDomain(domain)
    if (tf) domainSummaries.push(tf.summary)

    if (domainSummaries.length > 0) {
      summaries.push(`Domain ${domain}: ${domainSummaries.join(" | ")}`)
    }
  }

  for (const url of indicators.urls.slice(0, 2)) {
    const urlSummaries: string[] = []
    const uh = await urlhaus.lookupUrl(url)
    if (uh) urlSummaries.push(uh.summary)
    const tf = await threatfox.lookupUrl(url)
    if (tf) urlSummaries.push(tf.summary)
    if (gsbKey) {
      const gsb = await googleSafeBrowsing.lookupUrl(url, gsbKey)
      if (gsb) urlSummaries.push(gsb.summary)
    }
    if (urlSummaries.length > 0) {
      summaries.push(`URL ${url}: ${urlSummaries.join(" | ")}`)
    }
  }

  for (const hash of indicators.hashes.slice(0, 3)) {
    const hashSummaries: string[] = []
    const tf = await threatfox.lookupHash(hash)
    if (tf) hashSummaries.push(tf.summary)
    if (vtKey) {
      const vt = await virustotal.lookupHash(hash, vtKey)
      if (vt) hashSummaries.push(vt.summary)
    }
    if (hashSummaries.length > 0) {
      summaries.push(`Hash ${hash}: ${hashSummaries.join(" | ")}`)
    }
  }

  if (indicators.filenames.length > 0) {
    summaries.push(`Observed filenames/paths: ${indicators.filenames.slice(0, 5).join(", ")}`)
  }

  return {
    summary:
      summaries.length > 0
        ? summaries.join(" || ")
        : "No external threat intelligence hits from no-key feeds (URLhaus, ThreatFox, Spamhaus DROP) and configured key-based feeds.",
    geoCountry,
    geoCity,
    asnInfo,
  }
}
