import { NextRequest, NextResponse } from "next/server"
import { getAlertById } from "@/lib/db/alerts"
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

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const auth = await validateApiKey(request)
  if (!auth.ok) {
    return NextResponse.json({ error: auth.error }, { status: auth.status })
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
