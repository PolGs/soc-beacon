interface GeoIPResult {
  country: string
  city: string
  isp: string
  org: string
  asn: string
}

export async function lookupIP(ip: string): Promise<GeoIPResult | null> {
  // Skip private/reserved IPs
  if (isPrivateIP(ip)) return null

  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=country,city,isp,org,as`)
    if (!res.ok) return null
    const data = await res.json()

    if (data.status === "fail") return null

    return {
      country: data.country || "",
      city: data.city || "",
      isp: data.isp || "",
      org: data.org || "",
      asn: data.as || "",
    }
  } catch {
    return null
  }
}

function isPrivateIP(ip: string): boolean {
  const parts = ip.split(".").map(Number)
  if (parts.length !== 4) return true
  if (parts[0] === 10) return true
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true
  if (parts[0] === 192 && parts[1] === 168) return true
  if (parts[0] === 127) return true
  if (parts[0] === 0) return true
  return false
}
