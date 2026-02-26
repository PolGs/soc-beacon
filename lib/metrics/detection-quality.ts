import { getAlerts } from "@/lib/db/alerts"

type LabeledVerdict = "malicious" | "false_positive"

export interface DetectorQualityMetric {
  detector: string
  tp: number
  fp: number
  precision: number
  recall: number
}

export interface SourceQualityMetric {
  source: string
  tp: number
  fp: number
  precision: number
  recall: number
}

export interface DetectionQualityReport {
  labeledCount: number
  truePositiveCount: number
  falsePositiveCount: number
  detectors: DetectorQualityMetric[]
  bySource: SourceQualityMetric[]
}

function pct(numerator: number, denominator: number): number {
  if (denominator <= 0) return 0
  return Math.round((numerator / denominator) * 100)
}

export async function getDetectionQualityReport(limit = 2000): Promise<DetectionQualityReport> {
  const alerts = await getAlerts({ limit: Math.max(100, Math.min(10_000, limit)) })
  const labeled = alerts.filter((a) => a.verdict === "malicious" || a.verdict === "false_positive")
  const tpTotal = labeled.filter((a) => a.verdict === "malicious").length
  const fpTotal = labeled.filter((a) => a.verdict === "false_positive").length

  const detectors: Array<{ name: string; hit: (a: (typeof labeled)[number]) => boolean }> = [
    { name: "sigma", hit: (a) => Boolean(a.enrichment.sigma) },
    { name: "yara", hit: (a) => Boolean(a.yaraMatch) },
    { name: "threat_intel", hit: (a) => Boolean((a.enrichment.threatIntelVendors || []).some((v) => v.hit)) },
    { name: "ai_suspicious_plus", hit: (a) => (a.enrichment.aiScore || 0) >= 45 },
  ]

  const detectorMetrics: DetectorQualityMetric[] = detectors.map((d) => {
    let tp = 0
    let fp = 0
    for (const a of labeled) {
      if (!d.hit(a)) continue
      if (a.verdict === "malicious") tp += 1
      if (a.verdict === "false_positive") fp += 1
    }
    return {
      detector: d.name,
      tp,
      fp,
      precision: pct(tp, tp + fp),
      recall: pct(tp, tpTotal),
    }
  })

  const bySourceMap = new Map<string, { tp: number; fp: number }>()
  for (const a of labeled) {
    const key = (a.source || "unknown").trim() || "unknown"
    const current = bySourceMap.get(key) || { tp: 0, fp: 0 }
    if (a.verdict === "malicious") current.tp += 1
    if (a.verdict === "false_positive") current.fp += 1
    bySourceMap.set(key, current)
  }

  const bySource: SourceQualityMetric[] = Array.from(bySourceMap.entries())
    .map(([source, counts]) => ({
      source,
      tp: counts.tp,
      fp: counts.fp,
      precision: pct(counts.tp, counts.tp + counts.fp),
      recall: pct(counts.tp, tpTotal),
    }))
    .sort((a, b) => (b.tp + b.fp) - (a.tp + a.fp))
    .slice(0, 10)

  return {
    labeledCount: labeled.length,
    truePositiveCount: tpTotal,
    falsePositiveCount: fpTotal,
    detectors: detectorMetrics,
    bySource,
  }
}

