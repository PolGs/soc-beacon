import { NextRequest, NextResponse } from "next/server"
import { getLogs } from "@/lib/db/logs"
import { ingestLog } from "@/lib/pipeline"
import { validateApiKeyWithRateLimit } from "@/lib/security/api-auth"

export async function GET(request: NextRequest) {
  const auth = await validateApiKeyWithRateLimit(request, "v1:logs:get", 180, 60_000)
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
  const auth = await validateApiKeyWithRateLimit(request, "v1:logs:post", 240, 60_000)
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
