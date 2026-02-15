"use client"

import { useState } from "react"
import { cn } from "@/lib/utils"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { toast } from "sonner"
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
  Plus,
  Trash2,
  User,
  Lock,
} from "lucide-react"

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

export function SettingsView() {
  // General
  const [instanceName, setInstanceName] = useState("SOC Beacon - Production")
  const [retentionDays, setRetentionDays] = useState("90")

  // Syslog Input
  const [syslogEnabled, setSyslogEnabled] = useState(true)
  const [syslogPort, setSyslogPort] = useState("514")
  const [syslogProtocol, setSyslogProtocol] = useState<"udp" | "tcp" | "both">("both")
  const [syslogTls, setSyslogTls] = useState(false)

  // API Ingestion
  const [apiEnabled, setApiEnabled] = useState(true)
  const [apiPort, setApiPort] = useState("8443")
  const [apiKey, setApiKey] = useState("sk-beacon-prod-a1b2c3d4e5f6g7h8")

  // LLM Configuration
  const [llmProvider, setLlmProvider] = useState<"openai" | "anthropic" | "local" | "custom">("openai")
  const [llmApiKey, setLlmApiKey] = useState("")
  const [llmModel, setLlmModel] = useState("gpt-4o")
  const [llmEndpoint, setLlmEndpoint] = useState("https://api.openai.com/v1")
  const [llmMaxTokens, setLlmMaxTokens] = useState("4096")
  const [llmTemperature, setLlmTemperature] = useState("0.1")
  const [autoEnrich, setAutoEnrich] = useState(true)

  // YARA Rules
  const [yaraEnabled, setYaraEnabled] = useState(true)
  const [yaraRulesPath, setYaraRulesPath] = useState("/etc/socbeacon/rules/yara/")
  const [yaraAutoUpdate, setYaraAutoUpdate] = useState(true)
  const [customYaraRules, setCustomYaraRules] = useState([
    { name: "CobaltStrike_Beacon_Encoded", enabled: true },
    { name: "Mimikatz_Memory_Signature", enabled: true },
    { name: "PowerShell_Download_Cradle", enabled: true },
    { name: "OLE_Macro_Suspicious", enabled: true },
    { name: "Ransomware_Note_Strings", enabled: true },
  ])

  // Syslog Output
  const [syslogOutputEnabled, setSyslogOutputEnabled] = useState(true)
  const [syslogOutputHost, setSyslogOutputHost] = useState("10.0.0.50")
  const [syslogOutputPort, setSyslogOutputPort] = useState("5514")
  const [syslogOutputFormat, setSyslogOutputFormat] = useState<"cef" | "leef" | "json">("cef")

  // Threat Intel Feeds
  const [threatFeeds, setThreatFeeds] = useState([
    { name: "AlienVault OTX", url: "https://otx.alienvault.com/api/v1/", enabled: true },
    { name: "Abuse.ch URLhaus", url: "https://urlhaus-api.abuse.ch/v1/", enabled: true },
    { name: "VirusTotal", url: "https://www.virustotal.com/api/v3/", enabled: false },
  ])
  const [newFeedName, setNewFeedName] = useState("")
  const [newFeedUrl, setNewFeedUrl] = useState("")

  // Auth
  const [currentPassword, setCurrentPassword] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")

  const handleSave = (section: string) => {
    toast.success(`${section} settings saved`, {
      description: "Changes will take effect immediately.",
    })
  }

  const handleAddFeed = () => {
    if (newFeedName && newFeedUrl) {
      setThreatFeeds([...threatFeeds, { name: newFeedName, url: newFeedUrl, enabled: true }])
      setNewFeedName("")
      setNewFeedUrl("")
      toast.success("Threat feed added")
    }
  }

  const handleRemoveFeed = (index: number) => {
    setThreatFeeds(threatFeeds.filter((_, i) => i !== index))
    toast.success("Threat feed removed")
  }

  const handlePasswordChange = () => {
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
    toast.success("Password updated successfully")
    setCurrentPassword("")
    setNewPassword("")
    setConfirmPassword("")
  }

  return (
    <Tabs defaultValue="general" className="w-full">
      <TabsList className="bg-card/60 border border-border/50 h-9 p-1 flex-wrap">
        <TabsTrigger
          value="general"
          className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7"
        >
          <Radio className="w-3.5 h-3.5 mr-1.5" />
          General
        </TabsTrigger>
        <TabsTrigger
          value="ingestion"
          className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7"
        >
          <Server className="w-3.5 h-3.5 mr-1.5" />
          Ingestion
        </TabsTrigger>
        <TabsTrigger
          value="ai"
          className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7"
        >
          <Key className="w-3.5 h-3.5 mr-1.5" />
          AI / LLM
        </TabsTrigger>
        <TabsTrigger
          value="yara"
          className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7"
        >
          <FileCode className="w-3.5 h-3.5 mr-1.5" />
          YARA Rules
        </TabsTrigger>
        <TabsTrigger
          value="output"
          className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7"
        >
          <Send className="w-3.5 h-3.5 mr-1.5" />
          Output
        </TabsTrigger>
        <TabsTrigger
          value="threatintel"
          className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7"
        >
          <Shield className="w-3.5 h-3.5 mr-1.5" />
          Threat Intel
        </TabsTrigger>
        <TabsTrigger
          value="auth"
          className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7"
        >
          <Lock className="w-3.5 h-3.5 mr-1.5" />
          Authentication
        </TabsTrigger>
      </TabsList>

      {/* General */}
      <TabsContent value="general" className="mt-4 flex flex-col gap-5">
        <SectionCard
          title="Instance Configuration"
          description="General settings for this SOC Beacon instance"
          icon={Radio}
        >
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="instanceName" className="text-[11px] text-muted-foreground">
                Instance Name
              </Label>
              <Input
                id="instanceName"
                value={instanceName}
                onChange={(e) => setInstanceName(e.target.value)}
                className="bg-background/60 border-border/50 h-8 text-xs placeholder:text-muted-foreground/40 focus:border-foreground/30"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="retention" className="text-[11px] text-muted-foreground">
                Log Retention (days)
              </Label>
              <Input
                id="retention"
                type="number"
                value={retentionDays}
                onChange={(e) => setRetentionDays(e.target.value)}
                className="bg-background/60 border-border/50 h-8 text-xs placeholder:text-muted-foreground/40 focus:border-foreground/30"
              />
            </div>
          </div>
          <div className="flex justify-end">
            <Button
              size="sm"
              className="h-8 text-xs bg-foreground text-background hover:bg-foreground/90"
              onClick={() => handleSave("General")}
            >
              <Save className="w-3.5 h-3.5 mr-1.5" />
              Save
            </Button>
          </div>
        </SectionCard>
      </TabsContent>

      {/* Ingestion */}
      <TabsContent value="ingestion" className="mt-4 flex flex-col gap-5">
        {/* Syslog Input */}
        <SectionCard
          title="Syslog Receiver"
          description="Configure syslog ingestion endpoint for receiving logs from network devices"
          icon={Server}
        >
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
                  <Input
                    value={syslogPort}
                    onChange={(e) => setSyslogPort(e.target.value)}
                    className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30"
                  />
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[11px] text-muted-foreground">Protocol</Label>
                  <div className="flex items-center gap-1 h-8">
                    {(["udp", "tcp", "both"] as const).map((p) => (
                      <button
                        key={p}
                        onClick={() => setSyslogProtocol(p)}
                        className={cn(
                          "flex-1 h-full rounded text-[11px] uppercase font-mono transition-colors border",
                          syslogProtocol === p
                            ? "bg-foreground/10 border-foreground/30 text-foreground"
                            : "border-border/50 text-muted-foreground hover:text-foreground"
                        )}
                      >
                        {p}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[11px] text-muted-foreground">TLS Encryption</Label>
                  <div className="flex items-center gap-2 h-8">
                    <Switch checked={syslogTls} onCheckedChange={setSyslogTls} />
                    <span className="text-[11px] text-muted-foreground">
                      {syslogTls ? "Enabled" : "Disabled"}
                    </span>
                  </div>
                </div>
              </div>
              <div className="bg-background/40 rounded-md p-3 border border-border/20">
                <p className="text-[11px] text-muted-foreground font-mono">
                  {"Listening on "}
                  {syslogProtocol === "both" ? "UDP+TCP" : syslogProtocol.toUpperCase()}
                  {" "}:{syslogPort}
                  {syslogTls ? " (TLS)" : ""}
                </p>
              </div>
            </>
          )}
          <div className="flex justify-end">
            <Button
              size="sm"
              className="h-8 text-xs bg-foreground text-background hover:bg-foreground/90"
              onClick={() => handleSave("Syslog Receiver")}
            >
              <Save className="w-3.5 h-3.5 mr-1.5" />
              Save
            </Button>
          </div>
        </SectionCard>

        {/* API Ingestion */}
        <SectionCard
          title="API Ingestion"
          description="REST API endpoint for programmatic log submission"
          icon={Key}
        >
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
                  <Input
                    value={apiPort}
                    onChange={(e) => setApiPort(e.target.value)}
                    className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30"
                  />
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[11px] text-muted-foreground">API Key</Label>
                  <div className="flex items-center gap-2">
                    <PasswordInput
                      id="apiKey"
                      value={apiKey}
                      onChange={setApiKey}
                      placeholder="sk-beacon-..."
                    />
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-8 px-2 text-muted-foreground hover:text-foreground shrink-0"
                      onClick={() => {
                        setApiKey(`sk-beacon-${Math.random().toString(36).substring(2, 18)}`)
                        toast.success("API key regenerated")
                      }}
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                </div>
              </div>
              <div className="bg-background/40 rounded-md p-3 border border-border/20">
                <p className="text-[11px] text-muted-foreground mb-1">Endpoint:</p>
                <code className="text-[11px] font-mono text-foreground/70">
                  {"POST https://your-server:"}
                  {apiPort}/api/v1/logs
                </code>
              </div>
            </>
          )}
          <div className="flex justify-end">
            <Button
              size="sm"
              className="h-8 text-xs bg-foreground text-background hover:bg-foreground/90"
              onClick={() => handleSave("API Ingestion")}
            >
              <Save className="w-3.5 h-3.5 mr-1.5" />
              Save
            </Button>
          </div>
        </SectionCard>
      </TabsContent>

      {/* AI / LLM */}
      <TabsContent value="ai" className="mt-4 flex flex-col gap-5">
        <SectionCard
          title="LLM Provider Configuration"
          description="Configure the AI model used for log analysis and enrichment"
          icon={Key}
        >
          <div className="flex flex-col gap-1.5">
            <Label className="text-[11px] text-muted-foreground">Provider</Label>
            <div className="flex items-center gap-1 flex-wrap">
              {(
                [
                  { key: "openai", label: "OpenAI" },
                  { key: "anthropic", label: "Anthropic" },
                  { key: "local", label: "Local (Ollama)" },
                  { key: "custom", label: "Custom Endpoint" },
                ] as const
              ).map((p) => (
                <button
                  key={p.key}
                  onClick={() => setLlmProvider(p.key)}
                  className={cn(
                    "px-3 py-1.5 rounded text-xs transition-colors border",
                    llmProvider === p.key
                      ? "bg-foreground/10 border-foreground/30 text-foreground"
                      : "border-border/50 text-muted-foreground hover:text-foreground"
                  )}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">API Key</Label>
              <PasswordInput
                id="llmApiKey"
                value={llmApiKey}
                onChange={setLlmApiKey}
                placeholder={
                  llmProvider === "openai"
                    ? "sk-..."
                    : llmProvider === "anthropic"
                      ? "sk-ant-..."
                      : "Not required for local"
                }
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">Model</Label>
              <Input
                value={llmModel}
                onChange={(e) => setLlmModel(e.target.value)}
                placeholder="gpt-4o"
                className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">API Endpoint</Label>
              <Input
                value={llmEndpoint}
                onChange={(e) => setLlmEndpoint(e.target.value)}
                className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">Max Tokens</Label>
              <Input
                type="number"
                value={llmMaxTokens}
                onChange={(e) => setLlmMaxTokens(e.target.value)}
                className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">Temperature</Label>
              <Input
                type="number"
                step="0.1"
                min="0"
                max="2"
                value={llmTemperature}
                onChange={(e) => setLlmTemperature(e.target.value)}
                className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30"
              />
            </div>
          </div>

          <div className="flex items-center justify-between py-1">
            <div>
              <span className="text-xs text-foreground">Auto-Enrich Alerts</span>
              <p className="text-[11px] text-muted-foreground">
                Automatically send new alerts to LLM for analysis
              </p>
            </div>
            <Switch checked={autoEnrich} onCheckedChange={setAutoEnrich} />
          </div>

          <div className="bg-background/40 rounded-md p-3 border border-border/20">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-muted-foreground">System Prompt Preview</span>
            </div>
            <pre className="mt-2 text-[11px] font-mono text-foreground/50 leading-relaxed whitespace-pre-wrap">
{`You are a SOC analyst AI assistant. Analyze the following security log/alert and provide:
1. Detailed analysis of what occurred
2. Threat assessment and confidence level
3. IOC classification and MITRE ATT&CK mapping
4. Actionable recommendations for the SOC team
5. Related threat intelligence context

Be precise, technical, and actionable.`}
            </pre>
          </div>

          <div className="flex justify-end">
            <Button
              size="sm"
              className="h-8 text-xs bg-foreground text-background hover:bg-foreground/90"
              onClick={() => handleSave("LLM Configuration")}
            >
              <Save className="w-3.5 h-3.5 mr-1.5" />
              Save
            </Button>
          </div>
        </SectionCard>
      </TabsContent>

      {/* YARA Rules */}
      <TabsContent value="yara" className="mt-4 flex flex-col gap-5">
        <SectionCard
          title="YARA Rule Engine"
          description="Configure YARA rule scanning for incoming logs and payloads"
          icon={FileCode}
        >
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs text-foreground">Enable YARA Scanning</span>
              <p className="text-[11px] text-muted-foreground">
                Scan ingested logs against YARA rule sets
              </p>
            </div>
            <Switch checked={yaraEnabled} onCheckedChange={setYaraEnabled} />
          </div>

          {yaraEnabled && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[11px] text-muted-foreground">Rules Directory</Label>
                  <Input
                    value={yaraRulesPath}
                    onChange={(e) => setYaraRulesPath(e.target.value)}
                    className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30"
                  />
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[11px] text-muted-foreground">Auto-Update Rules</Label>
                  <div className="flex items-center gap-2 h-8">
                    <Switch checked={yaraAutoUpdate} onCheckedChange={setYaraAutoUpdate} />
                    <span className="text-[11px] text-muted-foreground">
                      {yaraAutoUpdate ? "Enabled (daily)" : "Disabled"}
                    </span>
                  </div>
                </div>
              </div>

              <div className="flex flex-col gap-2">
                <span className="text-[11px] text-muted-foreground font-medium">Active Rules</span>
                <div className="bg-background/40 rounded-md border border-border/20 divide-y divide-border/20">
                  {customYaraRules.map((rule, i) => (
                    <div key={rule.name} className="flex items-center justify-between px-3 py-2">
                      <div className="flex items-center gap-2">
                        <FileCode className="w-3 h-3 text-muted-foreground/60" />
                        <code className="text-[11px] font-mono text-foreground/70">{rule.name}</code>
                      </div>
                      <Switch
                        checked={rule.enabled}
                        onCheckedChange={(checked) => {
                          const updated = [...customYaraRules]
                          updated[i] = { ...updated[i], enabled: checked }
                          setCustomYaraRules(updated)
                        }}
                      />
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}

          <div className="flex justify-end">
            <Button
              size="sm"
              className="h-8 text-xs bg-foreground text-background hover:bg-foreground/90"
              onClick={() => handleSave("YARA Rules")}
            >
              <Save className="w-3.5 h-3.5 mr-1.5" />
              Save
            </Button>
          </div>
        </SectionCard>
      </TabsContent>

      {/* Output */}
      <TabsContent value="output" className="mt-4 flex flex-col gap-5">
        <SectionCard
          title="Syslog Output"
          description="Forward enriched alerts to external SIEMs via syslog"
          icon={Send}
        >
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs text-foreground">Enable Syslog Output</span>
              <p className="text-[11px] text-muted-foreground">
                Forward enriched alert data to your SIEM
              </p>
            </div>
            <Switch checked={syslogOutputEnabled} onCheckedChange={setSyslogOutputEnabled} />
          </div>

          {syslogOutputEnabled && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[11px] text-muted-foreground">Destination Host</Label>
                  <Input
                    value={syslogOutputHost}
                    onChange={(e) => setSyslogOutputHost(e.target.value)}
                    className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30"
                  />
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[11px] text-muted-foreground">Port</Label>
                  <Input
                    value={syslogOutputPort}
                    onChange={(e) => setSyslogOutputPort(e.target.value)}
                    className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30"
                  />
                </div>
                <div className="flex flex-col gap-1.5">
                  <Label className="text-[11px] text-muted-foreground">Output Format</Label>
                  <div className="flex items-center gap-1 h-8">
                    {(["cef", "leef", "json"] as const).map((f) => (
                      <button
                        key={f}
                        onClick={() => setSyslogOutputFormat(f)}
                        className={cn(
                          "flex-1 h-full rounded text-[11px] uppercase font-mono transition-colors border",
                          syslogOutputFormat === f
                            ? "bg-foreground/10 border-foreground/30 text-foreground"
                            : "border-border/50 text-muted-foreground hover:text-foreground"
                        )}
                      >
                        {f}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
              <div className="bg-background/40 rounded-md p-3 border border-border/20">
                <p className="text-[11px] text-muted-foreground mb-1">Output destination:</p>
                <code className="text-[11px] font-mono text-foreground/70">
                  {syslogOutputFormat.toUpperCase()} {"->"} {syslogOutputHost}:{syslogOutputPort}
                </code>
              </div>
            </>
          )}

          <div className="flex justify-end">
            <Button
              size="sm"
              className="h-8 text-xs bg-foreground text-background hover:bg-foreground/90"
              onClick={() => handleSave("Syslog Output")}
            >
              <Save className="w-3.5 h-3.5 mr-1.5" />
              Save
            </Button>
          </div>
        </SectionCard>
      </TabsContent>

      {/* Threat Intel */}
      <TabsContent value="threatintel" className="mt-4 flex flex-col gap-5">
        <SectionCard
          title="Threat Intelligence Feeds"
          description="Configure external threat intelligence sources for alert enrichment"
          icon={Shield}
        >
          <div className="flex flex-col gap-2">
            <div className="bg-background/40 rounded-md border border-border/20 divide-y divide-border/20">
              {threatFeeds.map((feed, i) => (
                <div key={feed.name} className="flex items-center justify-between px-3 py-2.5">
                  <div className="flex flex-col gap-0.5 flex-1 min-w-0">
                    <span className="text-xs text-foreground/80">{feed.name}</span>
                    <code className="text-[10px] font-mono text-muted-foreground/60 truncate">
                      {feed.url}
                    </code>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <Switch
                      checked={feed.enabled}
                      onCheckedChange={(checked) => {
                        const updated = [...threatFeeds]
                        updated[i] = { ...updated[i], enabled: checked }
                        setThreatFeeds(updated)
                      }}
                    />
                    <button
                      onClick={() => handleRemoveFeed(i)}
                      className="p-1 rounded hover:bg-foreground/10 transition-colors text-muted-foreground/40 hover:text-foreground/60"
                    >
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
                <Input
                  value={newFeedName}
                  onChange={(e) => setNewFeedName(e.target.value)}
                  placeholder="Feed name"
                  className="bg-background/60 border-border/50 h-8 text-xs focus:border-foreground/30 placeholder:text-muted-foreground/40"
                />
              </div>
              <div className="flex flex-col gap-1 flex-[2]">
                <Input
                  value={newFeedUrl}
                  onChange={(e) => setNewFeedUrl(e.target.value)}
                  placeholder="https://api.example.com/v1/"
                  className="bg-background/60 border-border/50 h-8 text-xs font-mono focus:border-foreground/30 placeholder:text-muted-foreground/40"
                />
              </div>
              <Button
                size="sm"
                variant="ghost"
                className="h-8 px-3 text-xs text-muted-foreground hover:text-foreground shrink-0"
                onClick={handleAddFeed}
              >
                <Plus className="w-3.5 h-3.5 mr-1" />
                Add
              </Button>
            </div>
          </div>

          <div className="flex justify-end">
            <Button
              size="sm"
              className="h-8 text-xs bg-foreground text-background hover:bg-foreground/90"
              onClick={() => handleSave("Threat Intel")}
            >
              <Save className="w-3.5 h-3.5 mr-1.5" />
              Save
            </Button>
          </div>
        </SectionCard>
      </TabsContent>

      {/* Authentication */}
      <TabsContent value="auth" className="mt-4 flex flex-col gap-5">
        <SectionCard
          title="Change Password"
          description="Update the admin account password"
          icon={User}
        >
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">Current Password</Label>
              <PasswordInput
                id="currentPassword"
                value={currentPassword}
                onChange={setCurrentPassword}
                placeholder="Enter current password"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">New Password</Label>
              <PasswordInput
                id="newPassword"
                value={newPassword}
                onChange={setNewPassword}
                placeholder="Enter new password"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label className="text-[11px] text-muted-foreground">Confirm Password</Label>
              <PasswordInput
                id="confirmPassword"
                value={confirmPassword}
                onChange={setConfirmPassword}
                placeholder="Confirm new password"
              />
            </div>
          </div>
          <div className="flex justify-end">
            <Button
              size="sm"
              className="h-8 text-xs bg-foreground text-background hover:bg-foreground/90"
              onClick={handlePasswordChange}
            >
              <Lock className="w-3.5 h-3.5 mr-1.5" />
              Update Password
            </Button>
          </div>
        </SectionCard>

        <SectionCard
          title="Session Management"
          description="View and manage active sessions"
          icon={Shield}
        >
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
    </Tabs>
  )
}
