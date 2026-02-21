import { NextRequest, NextResponse } from "next/server"
import { getAlerts } from "@/lib/db/alerts"
import { getSetting } from "@/lib/db/settings"

async function validateApiKey(request: NextRequest): Promise<boolean> {
  const apiSettings = await getSetting<{ enabled: boolean; apiKey: string }>("api", {
    enabled: true,
    apiKey: "",
  })
  if (!apiSettings.apiKey) return true
  const authHeader = request.headers.get("authorization")
  const apiKey = authHeader?.replace(/^Bearer\s+/i, "") || request.headers.get("x-api-key")
  return apiKey === apiSettings.apiKey
}

export async function GET(request: NextRequest) {
  if (!(await validateApiKey(request))) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
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
