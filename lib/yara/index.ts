import { getYaraRules } from "@/lib/db/yara-rules"

interface YaraMatch {
  ruleName: string
  matchedStrings: string[]
}

interface ParsedPattern {
  type: "string" | "hex" | "regex"
  value: string
  id: string
}

function parseYaraRuleStrings(content: string): ParsedPattern[] {
  const patterns: ParsedPattern[] = []
  const stringsMatch = content.match(/strings\s*:([\s\S]*?)(?:condition\s*:|$)/)
  if (!stringsMatch) return patterns

  const stringsBlock = stringsMatch[1]
  const lines = stringsBlock.split("\n")

  for (const line of lines) {
    const trimmed = line.trim()

    // String pattern: $name = "value"
    const strMatch = trimmed.match(/^\$(\w+)\s*=\s*"([^"]*)"/)
    if (strMatch) {
      patterns.push({ type: "string", value: strMatch[2], id: strMatch[1] })
      continue
    }

    // Hex pattern: $name = { AA BB CC }
    const hexMatch = trimmed.match(/^\$(\w+)\s*=\s*\{\s*([^}]*)\s*\}/)
    if (hexMatch) {
      const hexStr = hexMatch[2].replace(/\s+/g, "").replace(/\?\?/g, "..")
      patterns.push({ type: "hex", value: hexStr, id: hexMatch[1] })
      continue
    }

    // Regex pattern: $name = /pattern/
    const regexMatch = trimmed.match(/^\$(\w+)\s*=\s*\/([^/]*)\//)
    if (regexMatch) {
      patterns.push({ type: "regex", value: regexMatch[2], id: regexMatch[1] })
      continue
    }
  }

  return patterns
}

function matchPatterns(content: string, patterns: ParsedPattern[]): string[] {
  const matched: string[] = []
  const contentLower = content.toLowerCase()

  for (const pattern of patterns) {
    try {
      if (pattern.type === "string") {
        if (contentLower.includes(pattern.value.toLowerCase())) {
          matched.push(`$${pattern.id}`)
        }
      } else if (pattern.type === "regex") {
        const regex = new RegExp(pattern.value, "i")
        if (regex.test(content)) {
          matched.push(`$${pattern.id}`)
        }
      } else if (pattern.type === "hex") {
        // Convert hex pattern to string for matching
        const hexClean = pattern.value.replace(/\.\./g, "")
        if (hexClean.length >= 4) {
          // Try to match at least partial hex sequences
          const bytes = hexClean.match(/.{2}/g)
          if (bytes) {
            const str = bytes.map((b) => String.fromCharCode(parseInt(b, 16))).join("")
            if (content.includes(str)) {
              matched.push(`$${pattern.id}`)
            }
          }
        }
      }
    } catch {
      // Skip invalid patterns
    }
  }

  return matched
}

export async function scanWithYara(content: string): Promise<YaraMatch | null> {
  const rules = await getYaraRules(true)

  for (const rule of rules) {
    const patterns = parseYaraRuleStrings(rule.content)
    if (patterns.length === 0) continue

    const matched = matchPatterns(content, patterns)

    // Check condition: by default require any match
    if (matched.length > 0) {
      return {
        ruleName: rule.name,
        matchedStrings: matched,
      }
    }
  }

  return null
}

export async function scanLogMessage(message: string): Promise<string | null> {
  const result = await scanWithYara(message)
  return result ? result.ruleName : null
}
