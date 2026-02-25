"use client"

import type { Alert, IncidentStatus, AlertVerdict } from "@/lib/types"
import { SeverityBadge } from "@/components/severity-badge"
import { StatusBadge } from "@/components/status-badge"
import { VerdictBadge } from "@/components/verdict-badge"
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
  RefreshCw,
  Search,
  Loader2,
  Trash2,
} from "lucide-react"
import { useState, useTransition } from "react"
import { useRouter } from "next/navigation"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { deleteAlertAction, updateAlertIncidentStatusAction, updateAlertVerdictAction, triggerEnrichmentAction, triggerThreatIntelAction } from "@/app/actions"
import { ScoreRing } from "@/components/score-ring"

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
  const router = useRouter()
  const [isPending, startTransition] = useTransition()
  const [enriching, setEnriching] = useState(false)
  const [threatIntelLoading, setThreatIntelLoading] = useState(false)
  const [deleting, setDeleting] = useState(false)

  const handleIncidentStatusChange = (incidentStatus: IncidentStatus) => {
    startTransition(() => {
      updateAlertIncidentStatusAction(alert.id, incidentStatus)
    })
  }

  const handleVerdictChange = (verdict: AlertVerdict) => {
    startTransition(() => {
      updateAlertVerdictAction(alert.id, verdict)
    })
  }

  const handleReEnrich = async () => {
    setEnriching(true)
    try {
      await triggerEnrichmentAction(alert.id)
    } finally {
      setEnriching(false)
    }
  }

  const handleThreatIntel = async () => {
    setThreatIntelLoading(true)
    try {
      await triggerThreatIntelAction(alert.id)
    } finally {
      setThreatIntelLoading(false)
    }
  }

  const handleDeleteAlert = async () => {
    const confirmed = window.confirm(`Delete alert ${alert.id}? This cannot be undone.`)
    if (!confirmed) return

    setDeleting(true)
    try {
      const result = await deleteAlertAction(alert.id)
      if (result.success) {
        router.push("/dashboard/alerts")
        router.refresh()
      }
    } finally {
      setDeleting(false)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="glass rounded-lg p-5">
        <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-3">
              <SeverityBadge severity={alert.severity} />
              <VerdictBadge verdict={alert.verdict} />
              <StatusBadge status={alert.incidentStatus} />
              <span className="text-[11px] font-mono text-muted-foreground">{alert.id}</span>
            </div>
            <h1 className="text-base font-semibold text-foreground">{alert.title}</h1>
            <p className="text-xs text-muted-foreground leading-relaxed max-w-2xl">
              {alert.description}
            </p>
          </div>
          <div className="flex flex-col items-end gap-2 shrink-0">
            <div className="flex flex-col items-end">
              <span className="text-[11px] text-muted-foreground">
                Alert: {new Date(alert.timestamp).toLocaleString()}
              </span>
              <span className="text-[11px] text-muted-foreground/70">
                Ingested: {new Date(alert.ingestedAt || alert.timestamp).toLocaleString()}
              </span>
            </div>
            <div className="flex items-center gap-3">
              <ScoreRing label="AI" score={alert.enrichment.aiScore} size={50} />
              <ScoreRing label="Heuristics" score={alert.enrichment.heuristicsScore} size={50} />
            </div>
            <div className="flex items-center gap-2 mt-1">
              <select
                value={alert.verdict}
                onChange={(e) => handleVerdictChange(e.target.value as AlertVerdict)}
                disabled={isPending}
                className="h-8 rounded-md border border-border/50 bg-background/60 px-2 text-[11px] text-foreground"
              >
                <option value="malicious">Malicious</option>
                <option value="suspicious">Suspicious</option>
                <option value="false_positive">False Positive</option>
              </select>
              <select
                value={alert.incidentStatus}
                onChange={(e) => handleIncidentStatusChange(e.target.value as IncidentStatus)}
                disabled={isPending}
                className="h-8 rounded-md border border-border/50 bg-background/60 px-2 text-[11px] text-foreground"
              >
                <option value="unassigned">Unassigned</option>
                <option value="in_progress">In Progress</option>
                <option value="resolved">Resolved</option>
              </select>
              <button
                onClick={handleReEnrich}
                disabled={enriching}
                className="h-8 rounded-md border border-border/50 px-2 text-[11px] text-muted-foreground hover:text-foreground hover:border-foreground/30 transition-colors disabled:opacity-60 flex items-center gap-1"
              >
                {enriching ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
                Re-analyze
              </button>
              <button
                onClick={handleDeleteAlert}
                disabled={deleting}
                className="h-8 rounded-md border border-[hsl(var(--severity-critical))]/40 bg-[hsl(var(--severity-critical))]/10 px-2 text-[11px] text-[hsl(var(--severity-critical))] hover:bg-[hsl(var(--severity-critical))]/20 disabled:opacity-60 flex items-center gap-1"
              >
                {deleting ? <Loader2 className="w-3 h-3 animate-spin" /> : <Trash2 className="w-3 h-3" />}
                Delete
              </button>
            </div>
          </div>
        </div>

        {/* Metadata grid */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mt-5 pt-5 border-t border-border/30">
            <MetaItem icon={Server} label="Source" value={alert.source} />
            <MetaItem icon={Globe} label="Source IP" value={alert.sourceIp} mono />
            <MetaItem icon={Target} label="Dest IP" value={alert.destIp} mono />
            <MetaItem icon={Shield} label="IOC Type" value={alert.enrichment.iocType} />
            <MetaItem icon={FileCode} label="Parse Confidence" value={`${Math.round(alert.enrichment.parseConfidence ?? 0)}%`} />
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
            value="sigma"
            className="text-xs data-[state=active]:bg-foreground/10 data-[state=active]:text-foreground h-7"
          >
            <FileCode className="w-3.5 h-3.5 mr-1.5" />
            Sigma Results
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
            {/* Re-enrich buttons */}
            <div className="flex items-center gap-2">
              <button
                onClick={handleReEnrich}
                disabled={enriching}
                className="flex items-center gap-1.5 px-3 py-1.5 text-[11px] rounded-md border border-border/50 text-muted-foreground hover:text-foreground hover:border-foreground/30 transition-colors disabled:opacity-50"
              >
                {enriching ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
                Re-analyze with LLM
              </button>
              <button
                onClick={handleThreatIntel}
                disabled={threatIntelLoading}
                className="flex items-center gap-1.5 px-3 py-1.5 text-[11px] rounded-md border border-border/50 text-muted-foreground hover:text-foreground hover:border-foreground/30 transition-colors disabled:opacity-50"
              >
                {threatIntelLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Search className="w-3 h-3" />}
                Lookup Threat Intel
              </button>
            </div>

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

        <TabsContent value="sigma" className="mt-4">
          <div className="glass rounded-lg p-5 flex flex-col gap-4">
            {alert.enrichment.sigma ? (
              <>
                <div className="flex flex-col gap-2">
                  <div className="flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-foreground/60" />
                    <h3 className="text-sm font-medium text-foreground">Matched Sigma Rule</h3>
                  </div>
                  <div className="bg-background/50 rounded-md p-4 border border-border/30">
                    <div className="flex flex-col gap-1">
                      <span className="text-xs text-foreground">{alert.enrichment.sigma.title}</span>
                      {alert.enrichment.sigma.ruleId && (
                        <span className="text-[11px] font-mono text-muted-foreground">{alert.enrichment.sigma.ruleId}</span>
                      )}
                      {alert.enrichment.sigma.description && (
                        <p className="text-[11px] text-foreground/70 mt-2">{alert.enrichment.sigma.description}</p>
                      )}
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-3">
                      <div className="bg-background/70 rounded-md p-3 border border-border/30">
                        <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">Level</span>
                        <p className="text-xs text-foreground mt-1">{alert.enrichment.sigma.level || "Unknown"}</p>
                      </div>
                      <div className="bg-background/70 rounded-md p-3 border border-border/30">
                        <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">Status</span>
                        <p className="text-xs text-foreground mt-1">{alert.enrichment.sigma.status || "Unknown"}</p>
                      </div>
                      <div className="bg-background/70 rounded-md p-3 border border-border/30">
                        <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">Source</span>
                        <p className="text-[11px] font-mono text-foreground/70 mt-1 truncate">{alert.enrichment.sigma.source || "Local"}</p>
                      </div>
                    </div>
                  </div>
                </div>

                {alert.enrichment.sigma.tags && alert.enrichment.sigma.tags.length > 0 && (
                  <div className="bg-background/50 rounded-md p-4 border border-border/30">
                    <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">Tags</span>
                    <div className="flex flex-wrap gap-2 mt-2">
                      {alert.enrichment.sigma.tags.map((tag) => (
                        <span key={tag} className="text-[11px] font-mono px-2 py-0.5 rounded bg-foreground/5 border border-border/30 text-foreground/70">
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {alert.enrichment.sigma.references && alert.enrichment.sigma.references.length > 0 && (
                  <div className="bg-background/50 rounded-md p-4 border border-border/30">
                    <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">References</span>
                    <div className="flex flex-col gap-1 mt-2">
                      {alert.enrichment.sigma.references.map((ref) => (
                        <code key={ref} className="text-[11px] font-mono text-foreground/70 break-all">{ref}</code>
                      ))}
                    </div>
                  </div>
                )}

                {alert.enrichment.sigma.condition && (
                  <div className="bg-background/50 rounded-md p-4 border border-border/30">
                    <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">Condition</span>
                    <p className="text-[11px] font-mono text-foreground/70 mt-2">{alert.enrichment.sigma.condition}</p>
                  </div>
                )}

                {alert.enrichment.sigma.matchDetails && alert.enrichment.sigma.matchDetails.length > 0 && (
                  <div className="bg-background/50 rounded-md p-4 border border-border/30">
                    <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">Matched Fields</span>
                    <div className="mt-2 space-y-2">
                      {alert.enrichment.sigma.matchDetails.map((detail, i) => (
                        <div key={`${detail.field}-${i}`} className="flex flex-col md:flex-row md:items-center md:justify-between gap-2 bg-background/70 rounded-md p-3 border border-border/30">
                          <div className="flex flex-col">
                            <span className="text-[11px] text-muted-foreground">Selection</span>
                            <span className="text-xs text-foreground">{detail.selection}</span>
                          </div>
                          <div className="flex flex-col">
                            <span className="text-[11px] text-muted-foreground">Field</span>
                            <span className="text-xs font-mono text-foreground/80">{detail.field}</span>
                          </div>
                          <div className="flex flex-col">
                            <span className="text-[11px] text-muted-foreground">Operator</span>
                            <span className="text-xs font-mono text-foreground/80">{detail.operator}</span>
                          </div>
                          <div className="flex flex-col">
                            <span className="text-[11px] text-muted-foreground">Expected</span>
                            <span className="text-xs font-mono text-foreground/80">{detail.expected}</span>
                          </div>
                          <div className="flex flex-col">
                            <span className="text-[11px] text-muted-foreground">Actual</span>
                            <span className="text-xs font-mono text-foreground/80">{detail.actual}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="bg-background/50 rounded-md p-4 border border-border/30 text-xs text-muted-foreground">
                No Sigma rule matched this alert.
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
