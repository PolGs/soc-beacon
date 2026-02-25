import fs from "fs"
import path from "path"
import YAML from "yaml"
import { getSetting } from "@/lib/db/settings"
import type { Severity, SigmaMatch, SigmaMatchDetail } from "@/lib/types"
import { extractStructuredFields } from "@/lib/ingestion/structured-fields"
import { systemLog } from "@/lib/system-log"

interface SigmaSettings {
  enabled: boolean
  rulesPath: string
  maxRules: number
  lastSyncAt?: string
  lastSyncStatus?: "success" | "error"
  lastSyncError?: string
}

export interface SigmaClassification {
  title: string
  description: string
  severity: Severity
  mitreTactic: string
  mitreTechnique: string
}

export interface SigmaMatchResult {
  classification: SigmaClassification
  sigma: SigmaMatch
  parseConfidence: number
}

export interface SigmaStatus {
  enabled: boolean
  rulesPath: string
  maxRules: number
  totalFiles: number
  compiled: number
  lastSyncAt?: string
  lastSyncStatus?: "success" | "error"
  lastSyncError?: string
}

interface SigmaRule {
  id?: string
  title: string
  description?: string
  status?: string
  level?: string
  tags?: string[]
  references?: string[]
  author?: string
  logsource?: Record<string, string>
  detection: Record<string, unknown>
  condition: string
  source: string
}

interface SelectionMatch {
  matched: boolean
  details: SigmaMatchDetail[]
}

interface CompiledSigmaRule {
  rule: SigmaRule
  selections: Record<string, (event: SigmaEvent) => SelectionMatch>
  selectionNames: string[]
}

interface SigmaEvent {
  message: string
  source?: string
  fields: Record<string, unknown>
  fieldsLower: Record<string, unknown>
}

const cache = new Map<string, { loadedAt: number; rules: CompiledSigmaRule[] }>()

function mapSigmaLevel(level: string | undefined): Severity {
  const normalized = (level || "medium").toLowerCase().trim()
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

function extractTags(rule: Record<string, unknown>): string[] {
  const tags = rule.tags
  if (!tags) return []
  if (Array.isArray(tags)) return tags.map((t) => String(t))
  return [String(tags)]
}

function extractRefs(rule: Record<string, unknown>): string[] {
  const refs = (rule.references || rule.reference) as unknown
  if (!refs) return []
  if (Array.isArray(refs)) return refs.map((r) => String(r))
  return [String(refs)]
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

export async function getSigmaStatus(): Promise<SigmaStatus> {
  const settings = await getSetting<SigmaSettings>("sigma", {
    enabled: false,
    rulesPath: "",
    maxRules: 500,
  })

  if (!settings.rulesPath) {
    return {
      enabled: settings.enabled,
      rulesPath: "",
      maxRules: settings.maxRules || 500,
      totalFiles: 0,
      compiled: 0,
      lastSyncAt: settings.lastSyncAt,
      lastSyncStatus: settings.lastSyncStatus,
      lastSyncError: settings.lastSyncError,
    }
  }

  const totalFiles = listRuleFiles(settings.rulesPath).length
  const compiled = (await loadRulesFromPath(settings.rulesPath, settings.maxRules || 500)).length

  return {
    enabled: settings.enabled,
    rulesPath: settings.rulesPath,
    maxRules: settings.maxRules || 500,
    totalFiles,
    compiled,
    lastSyncAt: settings.lastSyncAt,
    lastSyncStatus: settings.lastSyncStatus,
    lastSyncError: settings.lastSyncError,
  }
}

function parseSigmaRule(content: string, source: string): SigmaRule | null {
  let doc: Record<string, unknown>
  try {
    doc = YAML.parse(content) as Record<string, unknown>
  } catch {
    return null
  }

  const title = String(doc.title || "").trim()
  const detection = doc.detection as Record<string, unknown>
  const condition = String(detection?.condition || "").trim()

  if (!title || !detection || !condition) return null

  return {
    id: doc.id ? String(doc.id) : undefined,
    title,
    description: doc.description ? String(doc.description) : undefined,
    status: doc.status ? String(doc.status) : undefined,
    level: doc.level ? String(doc.level) : undefined,
    tags: extractTags(doc),
    references: extractRefs(doc),
    author: doc.author ? String(doc.author) : undefined,
    logsource: (doc.logsource as Record<string, string>) || undefined,
    detection,
    condition,
    source,
  }
}

function tokenizeCondition(input: string): string[] {
  const tokens: string[] = []
  const re = /\s*(\(|\)|\band\b|\bor\b|\bnot\b|\ball\b|\bof\b|\d+|\w[\w*.-]*)\s*/gi
  let match: RegExpExecArray | null
  while ((match = re.exec(input)) !== null) {
    tokens.push(match[1])
  }
  return tokens
}

type ConditionNode =
  | { type: "and"; left: ConditionNode; right: ConditionNode }
  | { type: "or"; left: ConditionNode; right: ConditionNode }
  | { type: "not"; node: ConditionNode }
  | { type: "name"; name: string }
  | { type: "of"; count: number | "all"; names: string[] }

function buildConditionParser(selectionNames: string[], condition: string) {
  const tokens = tokenizeCondition(condition)
  let idx = 0

  const peek = () => tokens[idx]
  const consume = () => tokens[idx++]

  const expandNames = (pattern: string): string[] => {
    if (pattern === "them") return selectionNames
    if (pattern.includes("*")) {
      const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")
      const re = new RegExp(`^${escaped}$`, "i")
      return selectionNames.filter((name) => re.test(name))
    }
    return selectionNames.includes(pattern) ? [pattern] : []
  }

  const parsePrimary = (): ConditionNode => {
    const token = peek()
    if (!token) return { type: "name", name: "__invalid__" }
    if (token === "(") {
      consume()
      const node = parseOr()
      if (peek() === ")") consume()
      return node
    }
    if (token.toLowerCase() === "all" && tokens[idx + 1]?.toLowerCase() === "of") {
      consume()
      consume()
      const target = consume()
      return { type: "of", count: "all", names: expandNames(target) }
    }
    if (/^\d+$/.test(token) && tokens[idx + 1]?.toLowerCase() === "of") {
      const count = parseInt(token, 10)
      consume()
      consume()
      const target = consume()
      return { type: "of", count, names: expandNames(target) }
    }
    consume()
    return { type: "name", name: token }
  }

  const parseNot = (): ConditionNode => {
    const token = peek()
    if (token?.toLowerCase() === "not") {
      consume()
      return { type: "not", node: parseNot() }
    }
    return parsePrimary()
  }

  const parseAnd = (): ConditionNode => {
    let node = parseNot()
    while (peek()?.toLowerCase() === "and") {
      consume()
      node = { type: "and", left: node, right: parseNot() }
    }
    return node
  }

  const parseOr = (): ConditionNode => {
    let node = parseAnd()
    while (peek()?.toLowerCase() === "or") {
      consume()
      node = { type: "or", left: node, right: parseAnd() }
    }
    return node
  }

  const ast = parseOr()

  return (matches: Record<string, boolean>) => {
    const evalNode = (node: ConditionNode): boolean => {
      switch (node.type) {
        case "and":
          return evalNode(node.left) && evalNode(node.right)
        case "or":
          return evalNode(node.left) || evalNode(node.right)
        case "not":
          return !evalNode(node.node)
        case "name":
          return !!matches[node.name]
        case "of": {
          const selected = node.names.filter((n) => matches[n])
          if (node.count === "all") return node.names.length > 0 && selected.length === node.names.length
          return selected.length >= node.count
        }
        default:
          return false
      }
    }
    return evalNode(ast)
  }
}

function normalizeFieldValue(value: unknown): string[] {
  if (Array.isArray(value)) return value.map((v) => String(v))
  if (value === null || value === undefined) return []
  return [String(value)]
}

function wildcardToRegex(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")
  return new RegExp(`^${escaped}$`, "i")
}

function matchString(actual: string, expected: string, modifiers: string[]): boolean {
  const actualLower = actual.toLowerCase()
  const expectedLower = expected.toLowerCase()

  if (modifiers.includes("re") || modifiers.includes("regex")) {
    try {
      const re = new RegExp(expected)
      return re.test(actual)
    } catch {
      return false
    }
  }

  if (modifiers.includes("startswith")) return actualLower.startsWith(expectedLower)
  if (modifiers.includes("endswith")) return actualLower.endsWith(expectedLower)
  if (modifiers.includes("contains")) return actualLower.includes(expectedLower)

  if (expected.includes("*") || expected.includes("?")) {
    return wildcardToRegex(expected).test(actual)
  }

  return actualLower === expectedLower
}

function getEventFieldValues(event: SigmaEvent, field: string): string[] {
  const fieldKey = field.trim()
  if (!fieldKey) return []

  const direct = event.fields[fieldKey]
  if (direct !== undefined) return normalizeFieldValue(direct)

  const lowerKey = fieldKey.toLowerCase()
  if (lowerKey === "message" || lowerKey === "msg" || lowerKey === "log") return [event.message]
  if (lowerKey === "source" || lowerKey === "host" || lowerKey === "hostname") return event.source ? [event.source] : []

  const lower = event.fieldsLower[lowerKey]
  if (lower !== undefined) return normalizeFieldValue(lower)

  return []
}

function buildSelectionPredicate(selection: unknown, selectionName: string): (event: SigmaEvent) => SelectionMatch {
  const normalizeSelection = (input: unknown): Array<Record<string, unknown>> => {
    if (!input) return []
    if (Array.isArray(input)) return input.filter((v) => v && typeof v === "object") as Array<Record<string, unknown>>
    if (typeof input === "object") return [input as Record<string, unknown>]
    return []
  }

  const selections = normalizeSelection(selection)

  return (event: SigmaEvent) => {
    for (const sel of selections) {
      const details: SigmaMatchDetail[] = []
      let allMatch = true

      for (const [rawField, rawExpected] of Object.entries(sel)) {
        const fieldParts = rawField.split("|").map((p) => p.trim()).filter(Boolean)
        const field = fieldParts[0]
        const modifiers = fieldParts.slice(1).map((m) => m.toLowerCase())
        const values = getEventFieldValues(event, field)

        const expectedValues = Array.isArray(rawExpected) ? rawExpected : [rawExpected]
        const expectedStrings = expectedValues.map((v) => String(v))

        const requireAll = modifiers.includes("all")

        const matchExpected = (expected: string): { matched: boolean; actual: string } => {
          for (const actual of values) {
            if (matchString(actual, expected, modifiers)) return { matched: true, actual }
          }
          return { matched: false, actual: values[0] || "" }
        }

        if (requireAll) {
          for (const expected of expectedStrings) {
            const res = matchExpected(expected)
            if (!res.matched) {
              allMatch = false
              break
            }
            details.push({
              selection: selectionName,
              field,
              operator: modifiers.join("|") || "equals",
              expected,
              actual: res.actual,
            })
          }
          if (!allMatch) break
        } else {
          let anyMatched = false
          let matchedActual = ""
          for (const expected of expectedStrings) {
            const res = matchExpected(expected)
            if (res.matched) {
              anyMatched = true
              matchedActual = res.actual
              details.push({
                selection: selectionName,
                field,
                operator: modifiers.join("|") || "equals",
                expected,
                actual: matchedActual,
              })
              break
            }
          }
          if (!anyMatched) {
            allMatch = false
            break
          }
        }
      }

      if (allMatch) {
        return { matched: true, details }
      }
    }

    return { matched: false, details: [] }
  }
}

function compileRule(rule: SigmaRule): CompiledSigmaRule | null {
  const detection = rule.detection || {}
  const selections: Record<string, (event: SigmaEvent) => SelectionMatch> = {}
  const selectionNames: string[] = []

  for (const [key, value] of Object.entries(detection)) {
    if (key === "condition") continue
    selectionNames.push(key)
    selections[key] = buildSelectionPredicate(value, key)
  }

  if (selectionNames.length === 0) return null

  return { rule, selections, selectionNames }
}

async function loadRulesFromPath(rulesPath: string, maxRules: number): Promise<CompiledSigmaRule[]> {
  const key = `${rulesPath}:${maxRules}`
  const existing = cache.get(key)
  if (existing && Date.now() - existing.loadedAt < 30000) {
    return existing.rules
  }

  const files = listRuleFiles(rulesPath).slice(0, Math.max(1, maxRules))
  const rules: CompiledSigmaRule[] = []

  for (const file of files) {
    try {
      const content = fs.readFileSync(file, "utf8")
      const parsed = parseSigmaRule(content, file)
      if (!parsed) continue
      const compiled = compileRule(parsed)
      if (compiled) rules.push(compiled)
    } catch {
      // Ignore malformed files.
    }
  }

  systemLog("info", "sigma", "Loaded Sigma rules", {
    rulesPath,
    totalFiles: files.length,
    compiled: rules.length,
  })

  cache.set(key, { loadedAt: Date.now(), rules })
  return rules
}

function buildSigmaEvent(message: string, source?: string, parsedHint?: boolean): { event: SigmaEvent; confidence: number } {
  const structured = extractStructuredFields(message, parsedHint)
  const fields = structured.fields
  const fieldsLower: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(fields)) {
    fieldsLower[key.toLowerCase()] = value
  }
  return {
    event: {
      message,
      source,
      fields,
      fieldsLower,
    },
    confidence: structured.confidence,
  }
}

export async function classifyWithSigma(message: string, source?: string, parsedHint?: boolean): Promise<SigmaMatchResult | null> {
  const settings = await getSetting<SigmaSettings>("sigma", {
    enabled: false,
    rulesPath: "",
    maxRules: 500,
  })

  if (!settings.enabled || !settings.rulesPath) {
    systemLog("debug", "sigma", "Sigma disabled or rulesPath missing", { enabled: settings.enabled, rulesPath: settings.rulesPath })
    return null
  }
  const rules = await loadRulesFromPath(settings.rulesPath, settings.maxRules || 500)
  if (rules.length === 0) return null

  const { event, confidence } = buildSigmaEvent(message, source, parsedHint)

  systemLog("debug", "sigma", "Evaluating Sigma rules", {
    count: rules.length,
    source: source || "unknown",
  })

  for (const compiled of rules) {
    const selectionResults: Record<string, SelectionMatch> = {}
    const selectionMatchFlags: Record<string, boolean> = {}
    const selectionDetails: SigmaMatchDetail[] = []

    for (const name of compiled.selectionNames) {
      const result = compiled.selections[name](event)
      selectionResults[name] = result
      selectionMatchFlags[name] = result.matched
      if (result.matched) selectionDetails.push(...result.details)
    }

    const evaluateCondition = buildConditionParser(compiled.selectionNames, compiled.rule.condition)
    const matched = evaluateCondition(selectionMatchFlags)
    if (!matched) continue

    const tags = compiled.rule.tags || []
    const techniqueTag = tags.find((t) => /^attack\.t\d{4}(\.\d{3})?$/i.test(t))
    const tacticTag = tags.find((t) => /^attack\.[a-z0-9_-]+$/i.test(t) && !/^attack\.t/i.test(t))

    const result = {
      classification: {
        title: `Sigma: ${compiled.rule.title}`,
        description: compiled.rule.description || `Matched Sigma rule "${compiled.rule.title}".`,
        severity: mapSigmaLevel(compiled.rule.level),
        mitreTactic: tacticTag ? toTitleCase(tacticTag.replace(/^attack\./i, "")) : "Unknown",
        mitreTechnique: techniqueTag ? techniqueTag.replace(/^attack\./i, "").toUpperCase() : "Unknown",
      },
      sigma: {
        ruleId: compiled.rule.id,
        title: compiled.rule.title,
        level: compiled.rule.level,
        description: compiled.rule.description,
        author: compiled.rule.author,
        status: compiled.rule.status,
        references: compiled.rule.references,
        tags: compiled.rule.tags,
        logsource: compiled.rule.logsource,
        condition: compiled.rule.condition,
        selections: compiled.selectionNames.filter((n) => selectionMatchFlags[n]),
        matchDetails: selectionDetails,
        source: compiled.rule.source,
      },
      parseConfidence: confidence,
    }

    systemLog("info", "sigma", "Sigma rule matched", {
      title: result.sigma.title,
      ruleId: result.sigma.ruleId,
      selections: result.sigma.selections,
    })

    return result
  }

  return null
}
