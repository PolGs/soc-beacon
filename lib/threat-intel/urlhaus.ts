import { systemLog } from "@/lib/system-log"

interface UrlhausResult {
  summary: string
}

async function postForm(
  endpoint: string,
  formData: Record<string, string>
): Promise<Record<string, unknown> | null> {
  try {
    const body = new URLSearchParams(formData)
    const res = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body,
    })
    if (!res.ok) {
      systemLog("warn", "threat-intel", "URLhaus request failed", { endpoint, status: res.status })
      return null
    }
    return (await res.json()) as Record<string, unknown>
  } catch (err) {
    systemLog("error", "threat-intel", "URLhaus request error", { endpoint, error: String(err) })
    return null
  }
}

export async function lookupUrl(url: string): Promise<UrlhausResult | null> {
  const data = await postForm("https://urlhaus-api.abuse.ch/v1/url/", { url })
  if (!data) return null
  const status = String(data.query_status || "")
  if (status !== "ok") return null
  const tags = Array.isArray(data.tags) ? data.tags.join(", ") : "none"
  const threat = String(data.threat || "unknown")
  const host = String(data.host || "unknown")
  return {
    summary: `URLhaus: malicious URL hit (threat=${threat}, host=${host}, tags=${tags})`,
  }
}

export async function lookupHost(host: string): Promise<UrlhausResult | null> {
  const data = await postForm("https://urlhaus-api.abuse.ch/v1/host/", { host })
  if (!data) return null
  const status = String(data.query_status || "")
  if (status === "no_results" || status === "invalid_host") return null

  const urls = Array.isArray(data.urls) ? data.urls : []
  if (urls.length === 0) {
    return {
      summary: `URLhaus: host found with no active payload URLs (${host})`,
    }
  }

  return {
    summary: `URLhaus: host ${host} linked to ${urls.length} malicious URL entries`,
  }
}
