import { NextRequest, NextResponse } from "next/server"
import { getAlerts } from "@/lib/db/alerts"
import { getSetting } from "@/lib/db/settings"

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
