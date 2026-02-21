import { NextRequest, NextResponse } from "next/server"
import { getAlertById } from "@/lib/db/alerts"
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

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  if (!(await validateApiKey(request))) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const { id } = await params
  const alert = await getAlertById(id)

  if (!alert) {
    return NextResponse.json({ error: "Alert not found" }, { status: 404 })
  }

  const results: Record<string, unknown> = {}

  // LLM enrichment
  try {
    const { enrichAlertWithLLM } = await import("@/lib/llm/enrich")
    await enrichAlertWithLLM(id)
    results.llm = "success"
  } catch (err) {
    results.llm = `failed: ${err}`
  }

  // Threat intel enrichment
  try {
    const { enrichAlertWithThreatIntel } = await import("@/lib/threat-intel/enrich")
    await enrichAlertWithThreatIntel(id)
    results.threatIntel = "success"
  } catch (err) {
    results.threatIntel = `failed: ${err}`
  }

  const enrichedAlert = await getAlertById(id)
  return NextResponse.json({ alert: enrichedAlert, enrichmentResults: results })
}
