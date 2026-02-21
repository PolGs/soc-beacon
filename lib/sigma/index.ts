import fs from "fs"
import path from "path"
import { getSetting } from "@/lib/db/settings"
import type { Severity } from "@/lib/types"

interface SigmaSettings {
  enabled: boolean
  rulesPath: string
  maxRules: number
}

export interface SigmaClassification {
  title: string
  description: string
  severity: Severity
  mitreTactic: string
  mitreTechnique: string
}

interface ParsedSigmaRule {
  title: string
  severity: Severity
  mitreTactic: string
  mitreTechnique: string
  keywords: string[]
}

const cache = new Map<string, { loadedAt: number; rules: ParsedSigmaRule[] }>()

function mapSigmaLevel(level: string): Severity {
  const normalized = level.toLowerCase().trim()
  if (normalized === "critical") return "critical"
  if (normalized === "high") return "high"
  if (normalized === "medium") return "medium"
  if (normalized === "low") return "low"
  return "info"
}

function toTitleCase(value: string): string {
  return value
    .replace(/[_-]+/g, " ")
    .split(" ")
    .map((w) => (w ? w[0].toUpperCase() + w.slice(1) : w))
    .join(" ")
}

function extractTags(content: string): string[] {
  const match = content.match(/^tags:\s*$(?:\r?\n)([\s\S]*?)(?=^[a-zA-Z_]+\s*:|\Z)/m)
  if (!match) return []
  return match[1]
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.startsWith("- "))
    .map((l) => l.slice(2).trim())
}

function extractKeywords(content: string): string[] {
  const values: string[] = []

  const listBlockRegexes = [
    /keywords:\s*\r?\n((?:\s*-\s*.+\r?\n)+)/gi,
    /\|\s*contains\s*:\s*\r?\n((?:\s*-\s*.+\r?\n)+)/gi,
  ]

  for (const re of listBlockRegexes) {
    let match: RegExpExecArray | null
    while ((match = re.exec(content)) !== null) {
      const block = match[1]
      const items = block
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l.startsWith("- "))
        .map((l) => l.slice(2).trim().replace(/^['"]|['"]$/g, ""))
      values.push(...items)
    }
  }

  const scalarContains = content.matchAll(/[a-zA-Z0-9_.-]+\|contains\s*:\s*([^\r\n]+)/g)
  for (const m of scalarContains) {
    values.push(m[1].trim().replace(/^['"]|['"]$/g, ""))
  }

  return [...new Set(values)]
    .map((v) => v.trim())
    .filter((v) => v.length >= 3 && !v.includes("{") && !v.includes("}"))
    .slice(0, 40)
}

function parseRule(content: string): ParsedSigmaRule | null {
  const title = content.match(/^title:\s*(.+)$/m)?.[1]?.trim()
  if (!title) return null

  const level = content.match(/^level:\s*(.+)$/m)?.[1]?.trim() || "medium"
  const tags = extractTags(content)
  const keywords = extractKeywords(content)
  if (keywords.length === 0) return null

  const techniqueTag = tags.find((t) => /^attack\.t\d{4}(\.\d{3})?$/i.test(t))
  const tacticTag = tags.find((t) => /^attack\.[a-z0-9_-]+$/i.test(t) && !/^attack\.t/i.test(t))

  return {
    title,
    severity: mapSigmaLevel(level),
    mitreTechnique: techniqueTag ? techniqueTag.replace(/^attack\./i, "").toUpperCase() : "Unknown",
    mitreTactic: tacticTag ? toTitleCase(tacticTag.replace(/^attack\./i, "")) : "Unknown",
    keywords,
  }
}

function listRuleFiles(dir: string, out: string[] = []): string[] {
  if (!fs.existsSync(dir)) return out
  const entries = fs.readdirSync(dir, { withFileTypes: true })
  for (const entry of entries) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      listRuleFiles(full, out)
      continue
    }
    if (entry.isFile() && (full.endsWith(".yml") || full.endsWith(".yaml"))) {
      out.push(full)
    }
  }
  return out
}

async function loadRulesFromPath(rulesPath: string, maxRules: number): Promise<ParsedSigmaRule[]> {
  const key = `${rulesPath}:${maxRules}`
  const existing = cache.get(key)
  if (existing && Date.now() - existing.loadedAt < 30000) {
    return existing.rules
  }

  const files = listRuleFiles(rulesPath).slice(0, Math.max(1, maxRules))
  const rules: ParsedSigmaRule[] = []

  for (const file of files) {
    try {
      const content = fs.readFileSync(file, "utf8")
      const parsed = parseRule(content)
      if (parsed) rules.push(parsed)
    } catch {
      // Ignore malformed files.
    }
  }

  cache.set(key, { loadedAt: Date.now(), rules })
  return rules
}

export async function classifyWithSigma(message: string, source?: string): Promise<SigmaClassification | null> {
  const settings = await getSetting<SigmaSettings>("sigma", {
    enabled: false,
    rulesPath: "",
    maxRules: 500,
  })

  if (!settings.enabled || !settings.rulesPath) return null
  const rules = await loadRulesFromPath(settings.rulesPath, settings.maxRules || 500)
  if (rules.length === 0) return null

  const haystack = `${source || ""} ${message}`.toLowerCase()

  for (const rule of rules) {
    const matchedKeywords = rule.keywords.filter((k) => haystack.includes(k.toLowerCase()))
    if (matchedKeywords.length === 0) continue

    return {
      title: `Sigma: ${rule.title}`,
      description: `Matched Sigma rule "${rule.title}" via keywords: ${matchedKeywords.slice(0, 3).join(", ")}`,
      severity: rule.severity,
      mitreTactic: rule.mitreTactic,
      mitreTechnique: rule.mitreTechnique,
    }
  }

  return null
}
