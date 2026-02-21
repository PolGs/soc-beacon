interface AbuseIPDBResult {
  abuseConfidenceScore: number
  totalReports: number
  countryCode: string
  isp: string
  domain: string
  summary: string
}

export async function checkIP(ip: string, apiKey: string): Promise<AbuseIPDBResult | null> {
  try {
    const res = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      {
        headers: {
          Key: apiKey,
          Accept: "application/json",
        },
      }
    )
    if (!res.ok) return null
    const data = await res.json()
    const d = data.data
    if (!d) return null

    return {
      abuseConfidenceScore: d.abuseConfidenceScore || 0,
      totalReports: d.totalReports || 0,
      countryCode: d.countryCode || "",
      isp: d.isp || "",
      domain: d.domain || "",
      summary: `AbuseIPDB: ${d.abuseConfidenceScore}% abuse confidence, ${d.totalReports} reports, ISP: ${d.isp || "Unknown"}`,
    }
  } catch {
    return null
  }
}
