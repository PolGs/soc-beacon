import { NextRequest, NextResponse } from "next/server"
import { getLogs } from "@/lib/db/logs"
import { getSetting } from "@/lib/db/settings"
import { ingestLog } from "@/lib/pipeline"

async function validateApiKey(request: NextRequest): Promise<{ ok: boolean; status: number; error: string }> {
  const apiSettings = await getSetting<{ enabled: boolean; apiKey: string }>("api", {
    enabled: true,
    apiKey: "",
  })

  if (!apiSettings.enabled) {
    return { ok: false, status: 403, error: "API is disabled" }
  }

  if (!apiSettings.apiKey) {
    return { ok: false, status: 401, error: "API key is not configured" }
  }

  const authHeader = request.headers.get("authorization")
  const apiKey = authHeader?.replace(/^Bearer\s+/i, "") || request.headers.get("x-api-key")

  if (!apiKey || apiKey !== apiSettings.apiKey) {
    return { ok: false, status: 401, error: "Unauthorized" }
  }

  return { ok: true, status: 200, error: "" }
}

export async function GET(request: NextRequest) {
  const auth = await validateApiKey(request)
  if (!auth.ok) {
    return NextResponse.json({ error: auth.error }, { status: auth.status })
  }

  const { searchParams } = new URL(request.url)
  const limit = parseInt(searchParams.get("limit") || "100")
  const offset = parseInt(searchParams.get("offset") || "0")
  const source = searchParams.get("source") || undefined
  const severity = searchParams.get("severity") || undefined

  const logs = await getLogs({
    limit: Math.min(limit, 1000),
    offset,
    source,
    severity: severity as "critical" | "high" | "medium" | "low" | "info" | undefined,
  })

  return NextResponse.json({ logs, count: logs.length })
}

export async function POST(request: NextRequest) {
  const auth = await validateApiKey(request)
  if (!auth.ok) {
    return NextResponse.json({ error: auth.error }, { status: auth.status })
  }

  try {
    const body = await request.json()

    // Single log or array
    const entries = Array.isArray(body) ? body : [body]
    const results = []

    for (const entry of entries) {
      if (!entry.message && !entry.msg && !entry.log) {
        continue
      }

      const result = await ingestLog({
        timestamp: entry.timestamp || entry.time,
        source: entry.source || entry.host || "API",
        message: entry.message || entry.msg || entry.log,
        severity: entry.severity || entry.level,
      })

      results.push(result)
    }

    return NextResponse.json({
      ingested: results.length,
      alerts: results.filter((r) => r.alertId).length,
      results,
    })
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 })
  }
}
