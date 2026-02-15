"use client"

import type { Alert } from "@/lib/mock-data"
import { SeverityBadge } from "@/components/severity-badge"
import { StatusBadge } from "@/components/status-badge"
import {
  Brain,
  Shield,
  Globe,
  Server,
  FileCode,
  Terminal,
  Target,
  Lightbulb,
  Copy,
  Check,
} from "lucide-react"
import { useState } from "react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <button
      onClick={handleCopy}
      className="p-1 rounded hover:bg-foreground/10 transition-colors text-muted-foreground hover:text-foreground"
      aria-label="Copy to clipboard"
    >
      {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  )
}

export function AlertDetail({ alert }: { alert: Alert }) {
  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="glass rounded-lg p-5">
        <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-3">
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
              <span className="text-[11px] font-mono text-muted-foreground">{alert.id}</span>
            </div>
            <h1 className="text-base font-semibold text-foreground">{alert.title}</h1>
            <p className="text-xs text-muted-foreground leading-relaxed max-w-2xl">
              {alert.description}
            </p>
          </div>
          <div className="flex flex-col items-end gap-1.5 shrink-0">
            <span className="text-[11px] text-muted-foreground">
              {new Date(alert.timestamp).toLocaleString()}
            </span>
            <div className="flex items-center gap-1.5">
              <span className="text-[11px] text-muted-foreground">Confidence</span>
              <div className="w-16 h-1.5 rounded-full bg-foreground/10 overflow-hidden">
                <div
                  className="h-full rounded-full bg-foreground/70"
                  style={{ width: `${alert.enrichment.confidence}%` }}
                />
              </div>
              <span className="text-xs font-mono text-foreground tabular-nums">
                {alert.enrichment.confidence}%
              </span>
            </div>
          </div>
        </div>

        {/* Metadata grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-5 pt-5 border-t border-border/30">
          <MetaItem icon={Server} label="Source" value={alert.source} />
          <MetaItem icon={Globe} label="Source IP" value={alert.sourceIp} mono />
          <MetaItem icon={Target} label="Dest IP" value={alert.destIp} mono />
          <MetaItem icon={Shield} label="IOC Type" value={alert.enrichment.iocType} />
        </div>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="analysis" className="w-full">
        <TabsList className="bg-card/60 border border-border/50 h-9 p-1">
          <TabsTrigger
            value="analysis"
            className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7"
          >
            <Brain className="w-3.5 h-3.5 mr-1.5" />
            AI Analysis
          </TabsTrigger>
          <TabsTrigger
            value="mitre"
            className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7"
          >
            <Shield className="w-3.5 h-3.5 mr-1.5" />
            MITRE ATT&CK
          </TabsTrigger>
          <TabsTrigger
            value="enrichment"
            className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7"
          >
            <Lightbulb className="w-3.5 h-3.5 mr-1.5" />
            Enrichment
          </TabsTrigger>
          <TabsTrigger
            value="raw"
            className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7"
          >
            <Terminal className="w-3.5 h-3.5 mr-1.5" />
            Raw Log
          </TabsTrigger>
        </TabsList>

        <TabsContent value="analysis" className="mt-4">
          <div className="glass rounded-lg p-5 flex flex-col gap-5">
            {/* AI Analysis */}
            <div className="flex flex-col gap-3">
              <div className="flex items-center gap-2">
                <Brain className="w-4 h-4 text-foreground/60" />
                <h3 className="text-sm font-medium text-foreground">LLM Analysis</h3>
              </div>
              <div className="bg-background/50 rounded-md p-4 border border-border/30">
                <p className="text-xs text-foreground/80 leading-relaxed">
                  {alert.enrichment.aiAnalysis}
                </p>
              </div>
            </div>

            {/* Recommendations */}
            <div className="flex flex-col gap-3">
              <div className="flex items-center gap-2">
                <Lightbulb className="w-4 h-4 text-foreground/60" />
                <h3 className="text-sm font-medium text-foreground">Recommendations</h3>
              </div>
              <div className="bg-background/50 rounded-md p-4 border border-border/30">
                <div className="flex flex-col gap-2">
                  {alert.enrichment.recommendation.split(/\d+\.\s/).filter(Boolean).map((rec, i) => (
                    <div key={i} className="flex items-start gap-2">
                      <span className="text-[10px] font-mono text-muted-foreground shrink-0 mt-0.5 w-4 text-right">
                        {i + 1}.
                      </span>
                      <span className="text-xs text-foreground/80 leading-relaxed">{rec.trim()}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Threat Intelligence */}
            <div className="flex flex-col gap-3">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-foreground/60" />
                <h3 className="text-sm font-medium text-foreground">Threat Intelligence</h3>
              </div>
              <div className="bg-background/50 rounded-md p-4 border border-border/30">
                <p className="text-xs text-foreground/80 leading-relaxed">
                  {alert.enrichment.threatIntel}
                </p>
              </div>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="mitre" className="mt-4">
          <div className="glass rounded-lg p-5 flex flex-col gap-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-background/50 rounded-md p-4 border border-border/30">
                <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
                  Tactic
                </span>
                <p className="text-sm text-foreground mt-1">{alert.mitreTactic}</p>
              </div>
              <div className="bg-background/50 rounded-md p-4 border border-border/30">
                <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
                  Technique
                </span>
                <p className="text-sm text-foreground mt-1 font-mono text-xs">{alert.mitreTechnique}</p>
              </div>
            </div>
            {alert.yaraMatch && (
              <div className="bg-background/50 rounded-md p-4 border border-border/30">
                <div className="flex items-center gap-2 mb-2">
                  <FileCode className="w-3.5 h-3.5 text-foreground/60" />
                  <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
                    YARA Rule Match
                  </span>
                </div>
                <code className="text-xs font-mono text-foreground/80">{alert.yaraMatch}</code>
              </div>
            )}
            {alert.enrichment.relatedCves.length > 0 && (
              <div className="bg-background/50 rounded-md p-4 border border-border/30">
                <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
                  Related CVEs
                </span>
                <div className="flex flex-wrap gap-2 mt-2">
                  {alert.enrichment.relatedCves.map((cve) => (
                    <span
                      key={cve}
                      className="text-xs font-mono px-2 py-0.5 rounded bg-foreground/5 border border-border/30 text-foreground/70"
                    >
                      {cve}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="enrichment" className="mt-4">
          <div className="glass rounded-lg p-5 flex flex-col gap-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {alert.enrichment.geoLocation && (
                <div className="bg-background/50 rounded-md p-4 border border-border/30">
                  <div className="flex items-center gap-2 mb-2">
                    <Globe className="w-3.5 h-3.5 text-foreground/60" />
                    <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
                      Geolocation
                    </span>
                  </div>
                  <p className="text-sm text-foreground">
                    {alert.enrichment.geoLocation.city}, {alert.enrichment.geoLocation.country}
                  </p>
                </div>
              )}
              {alert.enrichment.asnInfo && (
                <div className="bg-background/50 rounded-md p-4 border border-border/30">
                  <div className="flex items-center gap-2 mb-2">
                    <Server className="w-3.5 h-3.5 text-foreground/60" />
                    <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
                      ASN Information
                    </span>
                  </div>
                  <p className="text-xs font-mono text-foreground/80">{alert.enrichment.asnInfo}</p>
                </div>
              )}
            </div>
            <div className="bg-background/50 rounded-md p-4 border border-border/30">
              <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
                IOC Classification
              </span>
              <p className="text-sm text-foreground mt-1">{alert.enrichment.iocType}</p>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="raw" className="mt-4">
          <div className="glass rounded-lg p-5">
            <div className="flex items-center justify-between mb-3">
              <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
                Raw Log Entry
              </span>
              <CopyButton text={alert.rawLog} />
            </div>
            <pre className="bg-background/80 rounded-md p-4 border border-border/30 overflow-x-auto">
              <code className="text-[11px] font-mono text-foreground/70 leading-relaxed whitespace-pre-wrap break-all">
                {alert.rawLog}
              </code>
            </pre>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  )
}

function MetaItem({
  icon: Icon,
  label,
  value,
  mono,
}: {
  icon: typeof Server
  label: string
  value: string
  mono?: boolean
}) {
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center gap-1.5">
        <Icon className="w-3 h-3 text-muted-foreground/60" />
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
          {label}
        </span>
      </div>
      <span className={`text-xs text-foreground/80 ${mono ? "font-mono" : ""}`}>{value}</span>
    </div>
  )
}
