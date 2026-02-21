interface VTResult {
  malicious: number
  suspicious: number
  harmless: number
  undetected: number
  summary: string
}

export async function lookupIP(ip: string, apiKey: string): Promise<VTResult | null> {
  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: { "x-apikey": apiKey },
    })
    if (!res.ok) return null
    const data = await res.json()
    const stats = data.data?.attributes?.last_analysis_stats || {}
    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      summary: `VT: ${stats.malicious || 0} malicious, ${stats.suspicious || 0} suspicious out of ${(stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0)} engines`,
    }
  } catch {
    return null
  }
}

export async function lookupDomain(domain: string, apiKey: string): Promise<VTResult | null> {
  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
      headers: { "x-apikey": apiKey },
    })
    if (!res.ok) return null
    const data = await res.json()
    const stats = data.data?.attributes?.last_analysis_stats || {}
    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      summary: `VT: ${stats.malicious || 0} malicious, ${stats.suspicious || 0} suspicious detections`,
    }
  } catch {
    return null
  }
}

export async function lookupHash(hash: string, apiKey: string): Promise<VTResult | null> {
  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { "x-apikey": apiKey },
    })
    if (!res.ok) return null
    const data = await res.json()
    const stats = data.data?.attributes?.last_analysis_stats || {}
    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      summary: `VT: ${stats.malicious || 0}/${(stats.malicious || 0) + (stats.harmless || 0) + (stats.undetected || 0)} engines flagged`,
    }
  } catch {
    return null
  }
}
