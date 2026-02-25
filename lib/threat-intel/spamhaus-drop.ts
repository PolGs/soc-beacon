import { systemLog } from "@/lib/system-log"

interface SpamhausResult {
  summary: string
}

let cache: { loadedAt: number; cidrs: string[] } = { loadedAt: 0, cidrs: [] }

function ipToInt(ip: string): number | null {
  const parts = ip.split(".").map((p) => Number(p))
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null
  return ((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + ((parts[2] << 8) >>> 0) + (parts[3] >>> 0)
}

function cidrContains(ip: string, cidr: string): boolean {
  const [base, bitsRaw] = cidr.split("/")
  const bits = Number(bitsRaw)
  if (!base || Number.isNaN(bits) || bits < 0 || bits > 32) return false

  const ipInt = ipToInt(ip)
  const baseInt = ipToInt(base)
  if (ipInt === null || baseInt === null) return false

  const mask = bits === 0 ? 0 : ((0xffffffff << (32 - bits)) >>> 0)
  return (ipInt & mask) === (baseInt & mask)
}

async function loadDropList(): Promise<string[]> {
  if (Date.now() - cache.loadedAt < 30 * 60 * 1000 && cache.cidrs.length > 0) {
    return cache.cidrs
  }

  try {
    const res = await fetch("https://www.spamhaus.org/drop/drop.txt")
    if (!res.ok) {
      systemLog("warn", "threat-intel", "Spamhaus DROP download failed", { status: res.status })
      return cache.cidrs
    }

    const text = await res.text()
    const cidrs = text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith(";"))
      .map((line) => line.split(";")[0].trim())
      .filter((line) => line.includes("/"))

    cache = { loadedAt: Date.now(), cidrs }
    return cidrs
  } catch (err) {
    systemLog("error", "threat-intel", "Spamhaus DROP download error", { error: String(err) })
    return cache.cidrs
  }
}

export async function lookupIP(ip: string): Promise<SpamhausResult | null> {
  const cidrs = await loadDropList()
  if (cidrs.length === 0) return null

  const hit = cidrs.find((cidr) => cidrContains(ip, cidr))
  if (!hit) return null

  return {
    summary: `Spamhaus DROP: IP ${ip} is within listed network ${hit}`,
  }
}
