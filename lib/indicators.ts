export interface ExtractedIndicators {
  ips: string[]
  urls: string[]
  domains: string[]
  hashes: string[]
  filenames: string[]
}

const URL_RE = /\bhttps?:\/\/[^\s"'<>()]+/gi
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g
const HASH_RE = /\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b/g
const DOMAIN_RE = /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b/g
const FILE_RE = /\b(?:[A-Za-z]:\\[^\s"'<>|]+|\/[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)+)\b/g

function unique(values: string[], limit: number): string[] {
  return [...new Set(values.map((v) => v.trim()).filter(Boolean))].slice(0, limit)
}

function stripPort(host: string): string {
  return host.replace(/:\d+$/, "")
}

function tryGetUrlHost(url: string): string | null {
  try {
    const parsed = new URL(url)
    return stripPort(parsed.hostname.toLowerCase())
  } catch {
    return null
  }
}

function isLikelyDomain(value: string): boolean {
  const lower = value.toLowerCase()
  if (lower === "localhost") return false
  if (/^\d+\.\d+\.\d+\.\d+$/.test(lower)) return false
  if (lower.endsWith(".local")) return false
  return true
}

function isIndicatorPath(value: string): boolean {
  return /[\\/]/.test(value) && /\.[A-Za-z0-9]{1,8}$/.test(value)
}

export function extractIndicators(text: string): ExtractedIndicators {
  const urls = unique(text.match(URL_RE) || [], 8)
  const ips = unique(text.match(IPV4_RE) || [], 12)
  const hashes = unique(text.match(HASH_RE) || [], 12)
  const filenames = unique((text.match(FILE_RE) || []).filter(isIndicatorPath), 12)

  const rawDomains = text.match(DOMAIN_RE) || []
  const urlDomains = urls
    .map(tryGetUrlHost)
    .filter((v): v is string => !!v)

  const domains = unique(
    [...rawDomains, ...urlDomains].map((d) => d.toLowerCase()).filter(isLikelyDomain),
    12
  )

  return { ips, urls, domains, hashes, filenames }
}
