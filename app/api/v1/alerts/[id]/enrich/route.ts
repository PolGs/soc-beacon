import { NextRequest, NextResponse } from "next/server"
import { getAlertById } from "@/lib/db/alerts"
import { validateApiKeyWithRateLimit } from "@/lib/security/api-auth"

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const auth = await validateApiKeyWithRateLimit(request, "v1:alerts:enrich", 90, 60_000)
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
