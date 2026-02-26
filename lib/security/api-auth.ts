import crypto from "crypto"
import type { NextRequest } from "next/server"
import { getSetting } from "@/lib/db/settings"
import { consumeRateLimit, hashActor } from "@/lib/security/rate-limit"

function safeEqualString(a: string, b: string): boolean {
  const aBuf = Buffer.from(a)
  const bBuf = Buffer.from(b)
  if (aBuf.length !== bBuf.length) return false
  return crypto.timingSafeEqual(aBuf, bBuf)
}

function getClientIp(request: NextRequest): string {
  const xff = request.headers.get("x-forwarded-for")
  if (xff) return xff.split(",")[0]?.trim() || "unknown"
  return request.headers.get("x-real-ip") || "unknown"
}

export async function validateApiKeyWithRateLimit(
  request: NextRequest,
  scope: string,
  limit = 120,
  windowMs = 60_000
): Promise<{ ok: boolean; status: number; error: string }> {
  const ip = getClientIp(request)
  const rl = consumeRateLimit({
    scope: `api:${scope}`,
    actor: hashActor(ip),
    limit,
    windowMs,
  })
  if (!rl.allowed) {
    return { ok: false, status: 429, error: "Too Many Requests" }
  }

  const apiSettings = await getSetting<{ enabled: boolean; apiKey: string }>("api", {
    enabled: true,
    apiKey: "",
  })
  if (!apiSettings.enabled) return { ok: false, status: 403, error: "API is disabled" }
  if (!apiSettings.apiKey) return { ok: false, status: 401, error: "API key is not configured" }

  const provided =
    request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ||
    request.headers.get("x-api-key") ||
    ""
  if (!provided || !safeEqualString(provided, apiSettings.apiKey)) {
    return { ok: false, status: 401, error: "Unauthorized" }
  }
  return { ok: true, status: 200, error: "" }
}

