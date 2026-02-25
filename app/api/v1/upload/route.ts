import { NextRequest, NextResponse } from "next/server"
import { parseLogFile } from "@/lib/ingestion/parser"
import { ingestLogsBatch } from "@/lib/pipeline"
import { getSetting } from "@/lib/db/settings"
import { getSession } from "@/lib/auth"

async function validateApiKey(request: NextRequest): Promise<{ ok: boolean; status: number; error: string }> {
  const session = await getSession()
  if (session) {
    return { ok: true, status: 200, error: "" }
  }

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

export async function POST(request: NextRequest) {
  const auth = await validateApiKey(request)
  if (!auth.ok) {
    return NextResponse.json({ error: auth.error }, { status: auth.status })
  }

  try {
    const formData = await request.formData()
    const file = formData.get("file") as File | null

    if (!file) {
      return NextResponse.json({ error: "No file provided" }, { status: 400 })
    }

    const content = await file.text()
    if (!content.trim()) {
      return NextResponse.json({ error: "File is empty" }, { status: 400 })
    }

    // Detect format from extension
    let format: string | undefined
    const name = file.name.toLowerCase()
    if (name.endsWith(".csv")) format = "csv"
    else if (name.endsWith(".json") || name.endsWith(".ndjson")) format = "json"
    else format = undefined // auto-detect

    const parsed = parseLogFile(content, format)

    if (parsed.length === 0) {
      return NextResponse.json({ error: "No valid log entries found in file" }, { status: 400 })
    }

    const result = await ingestLogsBatch(parsed)

    return NextResponse.json({
      logCount: result.logCount,
      alertCount: result.alertCount,
    })
  } catch (err) {
    console.error("[upload] Error:", err)
    return NextResponse.json({ error: "Failed to process upload" }, { status: 500 })
  }
}
