export type Severity = "critical" | "high" | "medium" | "low" | "info"
export type IncidentStatus = "unassigned" | "in_progress" | "resolved"
export type AlertVerdict = "malicious" | "suspicious" | "false_positive"
export type LLMProvider = "openai" | "anthropic" | "local" | "custom"

export interface AlertEnrichment {
  aiAnalysis: string
  iocType: string
  threatIntel: string
  recommendation: string
  aiScore: number
  heuristicsScore: number
  confidence?: number
  relatedCves: string[]
  geoLocation: { country: string; city: string } | null
  asnInfo: string | null
}

export interface Alert {
  id: string
  timestamp: string
  ingestedAt: string
  source: string
  sourceIp: string
  destIp: string
  severity: Severity
  title: string
  description: string
  yaraMatch: string | null
  mitreTactic: string
  mitreTechnique: string
  incidentStatus: IncidentStatus
  verdict: AlertVerdict
  enrichment: AlertEnrichment
  rawLog: string
}

export interface LogEntry {
  id: string
  timestamp: string
  source: string
  message: string
  severity: Severity
  parsed: boolean
}

export interface Settings {
  general: { instanceName: string; retentionDays: number }
  syslog: { enabled: boolean; port: number; protocol: "udp" | "tcp" | "both"; tls: boolean }
  api: { enabled: boolean; port: number; apiKey: string }
  llm: {
    provider: LLMProvider
    apiKey: string
    model: string
    endpoint: string
    maxTokens: number
    temperature: number
    autoEnrich: boolean
    analysisAgents?: number
    autoStatusConfidenceThreshold?: number
  }
  yara: { enabled: boolean; autoUpdate: boolean }
  sigma: { enabled: boolean; rulesPath: string; maxRules: number }
  syslogOutput: { enabled: boolean; host: string; port: number; format: "cef" | "leef" | "json" }
}

export interface YaraRule {
  id: string
  name: string
  content: string
  enabled: boolean
}

export interface ThreatFeed {
  id: string
  name: string
  url: string
  apiKey: string
  enabled: boolean
}
