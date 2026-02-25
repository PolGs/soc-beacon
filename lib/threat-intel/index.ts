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
import type { ThreatIntelVendorResult } from "@/lib/types"
import { systemLog } from "@/lib/system-log"

export interface ThreatIntelSnapshot {
  summary: string
  geoCountry: string | null
  geoCity: string | null
  asnInfo: string | null
  vendors: ThreatIntelVendorResult[]
}

function findFeedApiKey(feeds: Array<{ name: string; apiKey: string; enabled: boolean }>, pattern: RegExp): string | null {
  const feed = feeds.find((f) => f.enabled && pattern.test(f.name.toLowerCase()) && f.apiKey)
  return feed?.apiKey || null
}

function vendorRecord(
  vendor: string,
  indicator: string,
  indicatorType: ThreatIntelVendorResult["indicatorType"],
  result: { summary: string; hit?: boolean } | null,
  attempted: boolean
): ThreatIntelVendorResult {
  if (!attempted) {
    return { vendor, indicator, indicatorType, hit: false, clean: false, result: "Not configured", error: false }
  }
  if (!result) {
    return { vendor, indicator, indicatorType, hit: false, clean: true, result: "No hits found" }
  }
  const hit = result.hit ?? (result.summary.toLowerCase().includes("malicious") || result.summary.toLowerCase().includes("hit"))
  return { vendor, indicator, indicatorType, hit, clean: !hit, result: result.summary }
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
  const vendors: ThreatIntelVendorResult[] = []

  let geoCountry: string | null = null
  let geoCity: string | null = null
  let asnInfo: string | null = null

  const vtKey = findFeedApiKey(feeds, /virus\s*total|vt/)
  const abuseKey = findFeedApiKey(feeds, /abuse\s*ip|abuseipdb/)
  const otxKey = findFeedApiKey(feeds, /alien\s*vault|otx/)
  const gsbKey = findFeedApiKey(feeds, /google|safe\s*browsing/)

  // ── IPs ──
  for (const ip of indicators.ips.slice(0, 3)) {
    const ipSummaries: string[] = []

    if (vtKey) {
      const vt = await virustotal.lookupIP(ip, vtKey)
      const r = vendorRecord("VirusTotal", ip, "ip", vt ? { summary: vt.summary, hit: vt.malicious > 0 || vt.suspicious > 0 } : null, true)
      vendors.push(r)
      if (vt) ipSummaries.push(vt.summary)
    }
    if (abuseKey) {
      const abuse = await abuseipdb.checkIP(ip, abuseKey)
      const r = vendorRecord("AbuseIPDB", ip, "ip", abuse ? { summary: abuse.summary, hit: abuse.abuseConfidenceScore > 25 } : null, true)
      vendors.push(r)
      if (abuse) ipSummaries.push(abuse.summary)
    }
    if (otxKey) {
      const otx = await alienvault.lookupIP(ip, otxKey)
      const r = vendorRecord("AlienVault OTX", ip, "ip", otx ? { summary: otx.summary, hit: otx.pulseCount > 0 } : null, true)
      vendors.push(r)
      if (otx) ipSummaries.push(otx.summary)
    }

    const tf = await threatfox.lookupIP(ip)
    vendors.push(vendorRecord("ThreatFox", ip, "ip", tf, true))
    if (tf) ipSummaries.push(tf.summary)

    const drop = await spamhausDrop.lookupIP(ip)
    vendors.push(vendorRecord("Spamhaus DROP", ip, "ip", drop ? { summary: drop.summary, hit: true } : null, true))
    if (drop) ipSummaries.push(drop.summary)

    const geo = await geoip.lookupIP(ip)
    if (geo && !geoCountry) {
      geoCountry = geo.country || null
      geoCity = geo.city || null
      asnInfo = geo.asn && geo.isp ? `${geo.asn} - ${geo.isp}` : geo.asn || null
    }

    if (ipSummaries.length > 0) summaries.push(`IP ${ip}: ${ipSummaries.join(" | ")}`)
  }

  // ── Domains ──
  for (const domain of indicators.domains.slice(0, 3)) {
    const domainSummaries: string[] = []
    if (vtKey) {
      const vt = await virustotal.lookupDomain(domain, vtKey)
      const r = vendorRecord("VirusTotal", domain, "domain", vt ? { summary: vt.summary, hit: vt.malicious > 0 || vt.suspicious > 0 } : null, true)
      vendors.push(r)
      if (vt) domainSummaries.push(vt.summary)
    }
    if (otxKey) {
      const otx = await alienvault.lookupDomain(domain, otxKey)
      const r = vendorRecord("AlienVault OTX", domain, "domain", otx ? { summary: otx.summary, hit: otx.pulseCount > 0 } : null, true)
      vendors.push(r)
      if (otx) domainSummaries.push(otx.summary)
    }

    const uh = await urlhaus.lookupHost(domain)
    vendors.push(vendorRecord("URLhaus", domain, "domain", uh, true))
    if (uh) domainSummaries.push(uh.summary)

    const tf = await threatfox.lookupDomain(domain)
    vendors.push(vendorRecord("ThreatFox", domain, "domain", tf, true))
    if (tf) domainSummaries.push(tf.summary)

    if (domainSummaries.length > 0) summaries.push(`Domain ${domain}: ${domainSummaries.join(" | ")}`)
  }

  // ── URLs ──
  for (const url of indicators.urls.slice(0, 2)) {
    const urlSummaries: string[] = []

    const uh = await urlhaus.lookupUrl(url)
    vendors.push(vendorRecord("URLhaus", url, "url", uh ? { summary: uh.summary, hit: true } : null, true))
    if (uh) urlSummaries.push(uh.summary)

    const tf = await threatfox.lookupUrl(url)
    vendors.push(vendorRecord("ThreatFox", url, "url", tf, true))
    if (tf) urlSummaries.push(tf.summary)

    if (gsbKey) {
      const gsb = await googleSafeBrowsing.lookupUrl(url, gsbKey)
      vendors.push(vendorRecord("Google Safe Browsing", url, "url", gsb ? { summary: gsb.summary, hit: true } : null, true))
      if (gsb) urlSummaries.push(gsb.summary)
    }

    if (urlSummaries.length > 0) summaries.push(`URL ${url}: ${urlSummaries.join(" | ")}`)
  }

  // ── Hashes ──
  for (const hash of indicators.hashes.slice(0, 3)) {
    const hashSummaries: string[] = []

    const tf = await threatfox.lookupHash(hash)
    vendors.push(vendorRecord("ThreatFox", hash, "hash", tf, true))
    if (tf) hashSummaries.push(tf.summary)

    if (vtKey) {
      const vt = await virustotal.lookupHash(hash, vtKey)
      const r = vendorRecord("VirusTotal", hash, "hash", vt ? { summary: vt.summary, hit: vt.malicious > 0 || vt.suspicious > 0 } : null, true)
      vendors.push(r)
      if (vt) hashSummaries.push(vt.summary)
    }

    if (hashSummaries.length > 0) summaries.push(`Hash ${hash}: ${hashSummaries.join(" | ")}`)
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
    vendors,
  }
}
