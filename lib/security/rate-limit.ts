import crypto from "crypto"

type Bucket = {
  count: number
  resetAt: number
}

const buckets = new Map<string, Bucket>()

function now() {
  return Date.now()
}

function makeKey(scope: string, actor: string) {
  return `${scope}:${actor}`
}

export function consumeRateLimit(input: {
  scope: string
  actor: string
  limit: number
  windowMs: number
}): { allowed: boolean; retryAfterMs: number } {
  const key = makeKey(input.scope, input.actor || "unknown")
  const t = now()
  const existing = buckets.get(key)
  if (!existing || t >= existing.resetAt) {
    buckets.set(key, { count: 1, resetAt: t + input.windowMs })
    return { allowed: true, retryAfterMs: 0 }
  }

  if (existing.count >= input.limit) {
    return { allowed: false, retryAfterMs: Math.max(0, existing.resetAt - t) }
  }

  existing.count += 1
  buckets.set(key, existing)
  return { allowed: true, retryAfterMs: 0 }
}

export function hashActor(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex").slice(0, 16)
}

