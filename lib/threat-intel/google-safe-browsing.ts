import { systemLog } from "@/lib/system-log"

interface GoogleSafeBrowsingResult {
  summary: string
}

export async function lookupUrl(
  url: string,
  apiKey: string
): Promise<GoogleSafeBrowsingResult | null> {
  if (!apiKey) return null

  try {
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`
    const body = {
      client: {
        clientId: "soc-beacon",
        clientVersion: "1.0.0",
      },
      threatInfo: {
        threatTypes: [
          "MALWARE",
          "SOCIAL_ENGINEERING",
          "UNWANTED_SOFTWARE",
          "POTENTIALLY_HARMFUL_APPLICATION",
        ],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }],
      },
    }

    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
    if (!res.ok) {
      systemLog("warn", "threat-intel", "Google Safe Browsing lookup failed", { url, status: res.status })
      return null
    }

    const data = (await res.json()) as { matches?: Array<{ threatType?: string }> }
    const matches = data.matches || []
    if (matches.length === 0) {
      return { summary: "Google Safe Browsing: no known match." }
    }

    const types = [...new Set(matches.map((m) => m.threatType).filter(Boolean))]
    return {
      summary: `Google Safe Browsing: matched ${matches.length} entries (${types.join(", ")})`,
    }
  } catch (err) {
    systemLog("error", "threat-intel", "Google Safe Browsing lookup error", { url, error: String(err) })
    return null
  }
}
