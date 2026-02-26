import { NextRequest, NextResponse } from "next/server"
import { getSystemLogs, clearSystemLogs } from "@/lib/system-log"
import { getSession } from "@/lib/auth"
import { validateApiKeyWithRateLimit } from "@/lib/security/api-auth"

async function validateAccess(request: NextRequest): Promise<{ ok: boolean; status: number; error: string }> {
  const session = await getSession()
  if (session) return { ok: true, status: 200, error: "" }
  return validateApiKeyWithRateLimit(request, "v1:system-logs", 60, 60_000)
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
