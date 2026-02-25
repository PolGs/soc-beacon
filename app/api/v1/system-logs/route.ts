import { NextRequest, NextResponse } from "next/server"
import { getSystemLogs, clearSystemLogs } from "@/lib/system-log"
import { getSetting } from "@/lib/db/settings"
import { getSession } from "@/lib/auth"

async function validateAccess(request: NextRequest): Promise<{ ok: boolean; status: number; error: string }> {
  const session = await getSession()
  if (session) return { ok: true, status: 200, error: "" }

  const apiSettings = await getSetting<{ enabled: boolean; apiKey: string }>("api", {
    enabled: true,
    apiKey: "",
  })
  if (!apiSettings.enabled) return { ok: false, status: 403, error: "API is disabled" }
  if (!apiSettings.apiKey) return { ok: false, status: 401, error: "API key is not configured" }

  const authHeader = request.headers.get("authorization")
  const apiKey = authHeader?.replace(/^Bearer\s+/i, "") || request.headers.get("x-api-key")
  if (!apiKey || apiKey !== apiSettings.apiKey) {
    return { ok: false, status: 401, error: "Unauthorized" }
  }
  return { ok: true, status: 200, error: "" }
}

export async function GET(request: NextRequest) {
  const auth = await validateAccess(request)
  if (!auth.ok) return NextResponse.json({ error: auth.error }, { status: auth.status })

  const { searchParams } = new URL(request.url)
  const limit = parseInt(searchParams.get("limit") || "200")
  const since = searchParams.get("since") || undefined
  const logs = getSystemLogs(limit, since)
  return NextResponse.json({ logs })
}

export async function DELETE(request: NextRequest) {
  const auth = await validateAccess(request)
  if (!auth.ok) return NextResponse.json({ error: auth.error }, { status: auth.status })

  clearSystemLogs()
  return NextResponse.json({ cleared: true })
}
