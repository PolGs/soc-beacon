import { NextRequest, NextResponse } from "next/server"
import { getAlerts } from "@/lib/db/alerts"
import { validateApiKeyWithRateLimit } from "@/lib/security/api-auth"

export async function GET(request: NextRequest) {
  const auth = await validateApiKeyWithRateLimit(request, "v1:alerts:list", 180, 60_000)
  if (!auth.ok) {
    return NextResponse.json({ error: auth.error }, { status: auth.status })
  }

  const { searchParams } = new URL(request.url)
  const limit = parseInt(searchParams.get("limit") || "50")
  const offset = parseInt(searchParams.get("offset") || "0")
  const severity = searchParams.get("severity") || undefined
  const incidentStatusParam = searchParams.get("incidentStatus") || searchParams.get("status") || undefined
  const verdict = searchParams.get("verdict") || undefined
  const search = searchParams.get("search") || undefined

  let incidentStatus = incidentStatusParam
  if (incidentStatusParam === "new") incidentStatus = "unassigned"
  if (incidentStatusParam === "investigating") incidentStatus = "in_progress"

  const alerts = await getAlerts({
    limit: Math.min(limit, 500),
    offset,
    severity: severity as "critical" | "high" | "medium" | "low" | "info" | undefined,
    incidentStatus: incidentStatus as "unassigned" | "in_progress" | "resolved" | undefined,
    verdict: verdict as "malicious" | "suspicious" | "false_positive" | undefined,
    search,
  })

  return NextResponse.json({ alerts, count: alerts.length })
}
