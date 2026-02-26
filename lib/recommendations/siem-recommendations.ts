import { getAlerts } from "@/lib/db/alerts"
import { getDetectionQualityReport } from "@/lib/metrics/detection-quality"
import { getLLMClient } from "@/lib/llm"
import { getSetting } from "@/lib/db/settings"

export interface SiemRecommendationResult {
  generatedAt: string
  mode: "ai" | "heuristic"
  bullets: string[]
  context: {
    labeledAlerts: number
    malicious: number
    falsePositive: number
    criticalOpen: number
  }
}

function safeRatio(a: number, b: number): number {
  if (!b) return 0
  return Math.round((a / b) * 100)
}

function topEntries(map: Map<string, number>, limit = 5): Array<{ key: string; value: number }> {
  return Array.from(map.entries())
    .map(([key, value]) => ({ key, value }))
    .sort((x, y) => y.value - x.value)
    .slice(0, limit)
}

function fallbackBullets(input: {
  fpRate: number
  topFpSources: Array<{ key: string; value: number }>
  topCriticalSources: Array<{ key: string; value: number }>
  lowPrecisionDetectors: Array<{ detector: string; precision: number }>
}): string[] {
  const bullets: string[] = []

  if (input.fpRate >= 45) {
    bullets.push(
      `High false-positive pressure (${input.fpRate}%). Tighten source-side filtering and drop known benign events before forwarding to SOC Beacon.`
    )
  }

  if (input.topFpSources.length > 0) {
    const src = input.topFpSources[0]
    bullets.push(
      `Top false-positive source is "${src.key}" (${src.value} labeled FP alerts). Create source-specific suppression and severity remapping for noisy signatures.`
    )
  }

  if (input.topCriticalSources.length > 0) {
    const src = input.topCriticalSources[0]
    bullets.push(
      `Critical alert concentration is highest on "${src.key}" (${src.value} alerts). Review SIEM correlation rules for this source and require stronger multi-signal conditions before critical severity.`
    )
  }

  if (input.lowPrecisionDetectors.length > 0) {
    const d = input.lowPrecisionDetectors[0]
    bullets.push(
      `Detector "${d.detector}" has low precision (${d.precision}%). Add allow-lists and contextual constraints (asset role, change window, approved scanners) before escalation.`
    )
  }

  bullets.push(
    "Introduce pre-ingestion controls in upstream SIEM: deduplicate repeated events within short windows and forward only correlated incidents (not every raw match)."
  )
  bullets.push(
    "Adopt source-specific thresholds in SOC Beacon LLM policy to reduce over-escalation from historically noisy senders."
  )
  bullets.push(
    "Enforce analyst feedback loops: every false positive must map to a suppression/tuning action in the originating SIEM content pack."
  )

  return bullets.slice(0, 8)
}

function parseAiBullets(raw: string): string[] {
  try {
    const jsonMatch = raw.match(/\{[\s\S]*\}/)
    const obj = JSON.parse(jsonMatch ? jsonMatch[0] : raw) as { recommendations?: unknown }
    const arr = Array.isArray(obj.recommendations) ? obj.recommendations : []
    const bullets = arr
      .map((v) => String(v || "").trim())
      .filter(Boolean)
      .slice(0, 10)
    return bullets
  } catch {
    return raw
      .split(/\n+/)
      .map((line) => line.replace(/^\s*[-*0-9.)]+\s*/, "").trim())
      .filter(Boolean)
      .slice(0, 10)
  }
}

export async function generateSiemRecommendations(): Promise<SiemRecommendationResult> {
  const [alerts, quality, llm] = await Promise.all([
    getAlerts({ limit: 2500 }),
    getDetectionQualityReport(2500),
    getSetting<{ provider?: string; apiKey?: string; model?: string }>("llm", {}),
  ])

  const labeled = alerts.filter((a) => a.verdict === "malicious" || a.verdict === "false_positive")
  const malicious = labeled.filter((a) => a.verdict === "malicious").length
  const falsePositive = labeled.filter((a) => a.verdict === "false_positive").length
  const fpRate = safeRatio(falsePositive, labeled.length)
  const criticalOpen = alerts.filter((a) => a.severity === "critical" && a.incidentStatus !== "resolved").length

  const fpBySource = new Map<string, number>()
  const criticalBySource = new Map<string, number>()

  for (const alert of alerts) {
    const source = alert.source || "unknown"
    if (alert.verdict === "false_positive") fpBySource.set(source, (fpBySource.get(source) || 0) + 1)
    if (alert.severity === "critical" && alert.incidentStatus !== "resolved") {
      criticalBySource.set(source, (criticalBySource.get(source) || 0) + 1)
    }
  }

  const topFpSources = topEntries(fpBySource, 5)
  const topCriticalSources = topEntries(criticalBySource, 5)
  const lowPrecisionDetectors = quality.detectors
    .filter((d) => d.tp + d.fp > 0)
    .sort((a, b) => a.precision - b.precision)
    .slice(0, 3)
    .map((d) => ({ detector: d.detector, precision: d.precision }))

  const baseContext = {
    labeledAlerts: labeled.length,
    malicious,
    falsePositive,
    criticalOpen,
  }

  const heuristic = fallbackBullets({
    fpRate,
    topFpSources,
    topCriticalSources,
    lowPrecisionDetectors,
  })

  if (!llm?.apiKey || !llm?.provider || llm.provider === "local") {
    return {
      generatedAt: new Date().toISOString(),
      mode: "heuristic",
      bullets: heuristic,
      context: baseContext,
    }
  }

  try {
    const client = await getLLMClient()
    const system = `You are a SOC engineering assistant.
Return ONLY JSON:
{
  "recommendations": [
    "bullet 1",
    "bullet 2"
  ]
}
Rules:
- Focus on reducing noisy/false-positive critical alerts upstream in SIEM/data sources.
- Recommendations must be actionable and technical.
- Max 8 bullets.`
    const user = `Quality summary:
- labeled alerts: ${labeled.length}
- malicious: ${malicious}
- false_positive: ${falsePositive}
- false_positive_rate: ${fpRate}%
- open critical alerts: ${criticalOpen}

Low precision detectors:
${lowPrecisionDetectors.map((d) => `- ${d.detector}: ${d.precision}%`).join("\n") || "- none"}

Top false-positive sources:
${topFpSources.map((x) => `- ${x.key}: ${x.value}`).join("\n") || "- none"}

Top open critical sources:
${topCriticalSources.map((x) => `- ${x.key}: ${x.value}`).join("\n") || "- none"}

Provide prioritized recommendations for tuning SIEM and upstream senders so only high-quality tickets are forwarded.`

    const response = await client.chat([
      { role: "system", content: system },
      { role: "user", content: user },
    ])
    const bullets = parseAiBullets(response.content)
    return {
      generatedAt: new Date().toISOString(),
      mode: bullets.length > 0 ? "ai" : "heuristic",
      bullets: bullets.length > 0 ? bullets : heuristic,
      context: baseContext,
    }
  } catch {
    return {
      generatedAt: new Date().toISOString(),
      mode: "heuristic",
      bullets: heuristic,
      context: baseContext,
    }
  }
}

