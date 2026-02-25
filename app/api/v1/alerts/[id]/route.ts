import { NextRequest, NextResponse } from "next/server"
import { deleteAlert, getAlertById, updateAlertIncidentStatus, updateAlertVerdict } from "@/lib/db/alerts"
import { getSetting } from "@/lib/db/settings"
import type { IncidentStatus, AlertVerdict } from "@/lib/types"

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

export async function GET(
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

  return NextResponse.json(alert)
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const auth = await validateApiKey(request)
  if (!auth.ok) {
    return NextResponse.json({ error: auth.error }, { status: auth.status })
  }

  const { id } = await params
  const body = await request.json()
  const legacyStatus = body.status as string | undefined

  if (!body.incidentStatus && legacyStatus) {
    if (legacyStatus === "new") body.incidentStatus = "unassigned"
    if (legacyStatus === "investigating") body.incidentStatus = "in_progress"
    if (legacyStatus === "resolved") body.incidentStatus = "resolved"
    if (legacyStatus === "false_positive") {
      body.incidentStatus = "resolved"
      body.verdict = "false_positive"
    }
  }

  const validIncidentStatuses: IncidentStatus[] = ["unassigned", "in_progress", "resolved"]
  const validVerdicts: AlertVerdict[] = ["malicious", "suspicious", "false_positive"]

  if (body.incidentStatus && !validIncidentStatuses.includes(body.incidentStatus)) {
    return NextResponse.json({ error: "Invalid incidentStatus" }, { status: 400 })
  }
  if (body.verdict && !validVerdicts.includes(body.verdict)) {
    return NextResponse.json({ error: "Invalid verdict" }, { status: 400 })
  }

  if (body.incidentStatus) {
    await updateAlertIncidentStatus(id, body.incidentStatus)
  }
  if (body.verdict) {
    await updateAlertVerdict(id, body.verdict)
  }

  const alert = await getAlertById(id)
  return NextResponse.json(alert)
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const auth = await validateApiKey(request)
  if (!auth.ok) {
    return NextResponse.json({ error: auth.error }, { status: auth.status })
  }

  const { id } = await params
  const existing = await getAlertById(id)
  if (!existing) {
    return NextResponse.json({ error: "Alert not found" }, { status: 404 })
  }

  await deleteAlert(id)
  return NextResponse.json({ deleted: true, id })
}
