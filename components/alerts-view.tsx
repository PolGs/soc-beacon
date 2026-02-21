"use client"

import { useMemo, useState } from "react"
import Link from "next/link"
import type { Alert, Severity, IncidentStatus } from "@/lib/types"
import { SeverityBadge } from "@/components/severity-badge"
import { StatusBadge } from "@/components/status-badge"
import { VerdictBadge } from "@/components/verdict-badge"
import { ScoreRing } from "@/components/score-ring"
import { cn } from "@/lib/utils"
import { Search, Filter, ChevronRight, ArrowUpDown, Columns3 } from "lucide-react"
import { Input } from "@/components/ui/input"

const severityFilters: { key: Severity | "all"; label: string }[] = [
  { key: "all", label: "All" },
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "low", label: "Low" },
  { key: "info", label: "Info" },
]

const incidentStatusFilters: { key: IncidentStatus | "all"; label: string }[] = [
  { key: "all", label: "All" },
  { key: "unassigned", label: "Unassigned" },
  { key: "in_progress", label: "In Progress" },
  { key: "resolved", label: "Resolved" },
]

type SortKey =
  | "severity"
  | "id"
  | "title"
  | "source"
  | "mitreTactic"
  | "verdict"
  | "incidentStatus"
  | "aiScore"
  | "heuristicsScore"
  | "timestamp"
  | "ingestedAt"

type SortDirection = "asc" | "desc"

type ColumnKey =
  | "severity"
  | "id"
  | "alert"
  | "source"
  | "mitreTactic"
  | "verdict"
  | "incident"
  | "aiScore"
  | "heuristicsScore"
  | "times"

const columnLabels: Record<ColumnKey, string> = {
  severity: "Sev.",
  id: "ID",
  alert: "Alert",
  source: "Source",
  mitreTactic: "MITRE Tactic",
  verdict: "Verdict",
  incident: "Incident",
  aiScore: "AI Score",
  heuristicsScore: "Heuristics",
  times: "Times",
}

const defaultVisibleColumns: ColumnKey[] = [
  "severity",
  "id",
  "alert",
  "source",
  "verdict",
  "incident",
  "aiScore",
  "heuristicsScore",
  "times",
]

interface AlertsViewProps {
  initialAlerts: Alert[]
}

const severityWeight: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

function compareText(a: string, b: string): number {
  return a.localeCompare(b, undefined, { sensitivity: "base" })
}

function sortAlerts(items: Alert[], key: SortKey, direction: SortDirection): Alert[] {
  const sorted = [...items].sort((a, b) => {
    let result = 0
    switch (key) {
      case "severity":
        result = severityWeight[a.severity] - severityWeight[b.severity]
        break
      case "id":
        result = compareText(a.id, b.id)
        break
      case "title":
        result = compareText(a.title, b.title)
        break
      case "source":
        result = compareText(a.source, b.source)
        break
      case "mitreTactic":
        result = compareText(a.mitreTactic, b.mitreTactic)
        break
      case "verdict":
        result = compareText(a.verdict, b.verdict)
        break
      case "incidentStatus":
        result = compareText(a.incidentStatus, b.incidentStatus)
        break
      case "aiScore":
        result = (a.enrichment.aiScore || 0) - (b.enrichment.aiScore || 0)
        break
      case "heuristicsScore":
        result = (a.enrichment.heuristicsScore || 0) - (b.enrichment.heuristicsScore || 0)
        break
      case "ingestedAt":
        result = new Date(a.ingestedAt || a.timestamp).getTime() - new Date(b.ingestedAt || b.timestamp).getTime()
        break
      case "timestamp":
      default:
        result = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
        break
    }
    return direction === "asc" ? result : -result
  })
  return sorted
}

export function AlertsView({ initialAlerts }: AlertsViewProps) {
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all")
  const [incidentStatusFilter, setIncidentStatusFilter] = useState<IncidentStatus | "all">("all")
  const [searchQuery, setSearchQuery] = useState("")
  const [sortKey, setSortKey] = useState<SortKey>("timestamp")
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc")
  const [columnsOpen, setColumnsOpen] = useState(false)
  const [visibleColumns, setVisibleColumns] = useState<ColumnKey[]>(defaultVisibleColumns)

  const filtered = useMemo(() => {
    const base = initialAlerts.filter((a) => {
      if (severityFilter !== "all" && a.severity !== severityFilter) return false
      if (incidentStatusFilter !== "all" && a.incidentStatus !== incidentStatusFilter) return false
      if (searchQuery) {
        const q = searchQuery.toLowerCase()
        return (
          a.title.toLowerCase().includes(q) ||
          a.source.toLowerCase().includes(q) ||
          a.sourceIp.toLowerCase().includes(q) ||
          a.mitreTechnique.toLowerCase().includes(q)
        )
      }
      return true
    })
    return sortAlerts(base, sortKey, sortDirection)
  }, [incidentStatusFilter, initialAlerts, searchQuery, severityFilter, sortDirection, sortKey])

  const severityCounts = initialAlerts.reduce(
    (acc, a) => {
      acc[a.severity] = (acc[a.severity] || 0) + 1
      return acc
    },
    {} as Record<string, number>
  )

  function toggleColumn(column: ColumnKey) {
    setVisibleColumns((prev) => {
      if (prev.includes(column)) {
        if (prev.length === 1) return prev
        return prev.filter((c) => c !== column)
      }
      return [...prev, column]
    })
  }

  function handleSort(nextKey: SortKey) {
    if (sortKey === nextKey) {
      setSortDirection((prev) => (prev === "asc" ? "desc" : "asc"))
      return
    }
    setSortKey(nextKey)
    setSortDirection(nextKey === "timestamp" ? "desc" : "asc")
  }

  function thClasses(): string {
    return "text-[11px] font-medium text-muted-foreground text-left px-4 py-2.5 whitespace-nowrap"
  }

  const scoreColClass = "px-4 py-3 hidden xl:table-cell"

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        {severityFilters.map((f) => {
          const count = f.key === "all" ? initialAlerts.length : severityCounts[f.key] || 0
          return (
            <button
              key={f.key}
              onClick={() => setSeverityFilter(f.key)}
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs transition-colors border",
                severityFilter === f.key
                  ? "border-foreground/30 bg-foreground/10 text-foreground"
                  : "border-border/50 text-muted-foreground hover:text-foreground hover:border-foreground/20"
              )}
            >
              {f.label}
              <span className="text-[10px] tabular-nums opacity-60">{count}</span>
            </button>
          )
        })}
      </div>

      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input
            placeholder="Search alerts, IPs, techniques..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 h-8 text-xs bg-card/60 border-border/50 placeholder:text-muted-foreground/40"
          />
        </div>
        <div className="relative">
          <button
            onClick={() => setColumnsOpen((v) => !v)}
            className="h-8 px-2.5 rounded-md border border-border/50 bg-card/60 text-[11px] text-muted-foreground hover:text-foreground flex items-center gap-1.5"
          >
            <Columns3 className="w-3.5 h-3.5" />
            Columns
          </button>
          {columnsOpen && (
            <div className="absolute right-0 top-9 z-20 w-52 rounded-md border border-border/60 bg-card p-2 shadow-xl">
              {Object.keys(columnLabels).map((col) => {
                const key = col as ColumnKey
                return (
                  <label key={key} className="flex items-center gap-2 px-1.5 py-1 text-[11px] text-foreground/85">
                    <input
                      type="checkbox"
                      checked={visibleColumns.includes(key)}
                      onChange={() => toggleColumn(key)}
                      className="accent-foreground"
                    />
                    <span>{columnLabels[key]}</span>
                  </label>
                )
              })}
            </div>
          )}
        </div>
        <div className="flex items-center gap-1 px-2 py-1 rounded-md glass-subtle">
          <Filter className="w-3 h-3 text-muted-foreground" />
          {incidentStatusFilters.map((s) => (
            <button
              key={s.key}
              onClick={() => setIncidentStatusFilter(s.key)}
              className={cn(
                "px-2 py-0.5 text-[11px] rounded transition-colors capitalize",
                incidentStatusFilter === s.key
                  ? "bg-foreground/10 text-foreground"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      <div className="glass rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border/40 bg-muted/20">
                {visibleColumns.includes("severity") && (
                  <th className={thClasses()}>
                    <button onClick={() => handleSort("severity")} className="inline-flex items-center gap-1 hover:text-foreground">
                      Sev. <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                )}
                {visibleColumns.includes("id") && (
                  <th className={thClasses()}>
                    <button onClick={() => handleSort("id")} className="inline-flex items-center gap-1 hover:text-foreground">
                      ID <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                )}
                {visibleColumns.includes("alert") && (
                  <th className={thClasses()}>
                    <button onClick={() => handleSort("title")} className="inline-flex items-center gap-1 hover:text-foreground">
                      Alert <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                )}
                {visibleColumns.includes("source") && (
                  <th className={cn(thClasses(), "hidden md:table-cell")}>
                    <button onClick={() => handleSort("source")} className="inline-flex items-center gap-1 hover:text-foreground">
                      Source <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                )}
                {visibleColumns.includes("mitreTactic") && (
                  <th className={cn(thClasses(), "hidden lg:table-cell")}>
                    <button onClick={() => handleSort("mitreTactic")} className="inline-flex items-center gap-1 hover:text-foreground">
                      MITRE Tactic <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                )}
                {visibleColumns.includes("verdict") && (
                  <th className={cn(thClasses(), "hidden md:table-cell")}>
                    <button onClick={() => handleSort("verdict")} className="inline-flex items-center gap-1 hover:text-foreground">
                      Verdict <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                )}
                {visibleColumns.includes("incident") && (
                  <th className={cn(thClasses(), "hidden md:table-cell")}>
                    <button onClick={() => handleSort("incidentStatus")} className="inline-flex items-center gap-1 hover:text-foreground">
                      Incident <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                )}
                {visibleColumns.includes("aiScore") && (
                  <th className={cn(thClasses(), "hidden xl:table-cell")}>
                    <button onClick={() => handleSort("aiScore")} className="inline-flex items-center gap-1 hover:text-foreground">
                      AI Score <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                )}
                {visibleColumns.includes("heuristicsScore") && (
                  <th className={cn(thClasses(), "hidden xl:table-cell")}>
                    <button onClick={() => handleSort("heuristicsScore")} className="inline-flex items-center gap-1 hover:text-foreground">
                      Heuristics <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                )}
                {visibleColumns.includes("times") && (
                  <th className={thClasses()}>
                    <button onClick={() => handleSort("timestamp")} className="inline-flex items-center gap-1 hover:text-foreground">
                      Times <ArrowUpDown className="w-3 h-3" />
                    </button>
                  </th>
                )}
                <th className="w-8" />
              </tr>
            </thead>
            <tbody>
              {filtered.map((alert) => (
                <tr
                  key={alert.id}
                  className="border-b border-border/20 last:border-0 hover:bg-foreground/[0.02] transition-colors group"
                >
                  {visibleColumns.includes("severity") && (
                    <td className="px-4 py-3">
                      <SeverityBadge severity={alert.severity} />
                    </td>
                  )}
                  {visibleColumns.includes("id") && (
                    <td className="px-4 py-3">
                      <span className="text-[11px] font-mono text-muted-foreground">{alert.id}</span>
                    </td>
                  )}
                  {visibleColumns.includes("alert") && (
                    <td className="px-4 py-3">
                      <Link
                        href={`/dashboard/alerts/${alert.id}`}
                        className="text-xs text-foreground/90 hover:text-foreground font-medium transition-colors"
                      >
                        {alert.title}
                      </Link>
                      <p className="text-[11px] text-muted-foreground mt-0.5 max-w-md truncate">
                        {alert.description}
                      </p>
                    </td>
                  )}
                  {visibleColumns.includes("source") && (
                    <td className="px-4 py-3 hidden md:table-cell">
                      <div className="flex flex-col">
                        <span className="text-[11px] font-mono text-foreground/70">{alert.source}</span>
                        <span className="text-[10px] text-muted-foreground font-mono">{alert.sourceIp}</span>
                      </div>
                    </td>
                  )}
                  {visibleColumns.includes("mitreTactic") && (
                    <td className="px-4 py-3 hidden lg:table-cell">
                      <span className="text-[11px] text-muted-foreground">{alert.mitreTactic}</span>
                    </td>
                  )}
                  {visibleColumns.includes("verdict") && (
                    <td className="px-4 py-3 hidden md:table-cell">
                      <VerdictBadge verdict={alert.verdict} />
                    </td>
                  )}
                  {visibleColumns.includes("incident") && (
                    <td className="px-4 py-3 hidden md:table-cell">
                      <StatusBadge status={alert.incidentStatus} />
                    </td>
                  )}
                  {visibleColumns.includes("aiScore") && (
                    <td className={scoreColClass}>
                      <ScoreRing label="AI" score={alert.enrichment.aiScore} size={44} />
                    </td>
                  )}
                  {visibleColumns.includes("heuristicsScore") && (
                    <td className={scoreColClass}>
                      <ScoreRing label="Heur" score={alert.enrichment.heuristicsScore} size={44} />
                    </td>
                  )}
                  {visibleColumns.includes("times") && (
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-0.5">
                        <span className="text-[10px] text-muted-foreground/80 tabular-nums whitespace-nowrap">
                          Alert: {new Date(alert.timestamp).toLocaleTimeString("en-US", {
                            hour: "2-digit",
                            minute: "2-digit",
                          })}
                        </span>
                        <span className="text-[10px] text-muted-foreground/60 tabular-nums whitespace-nowrap">
                          Ingested: {new Date(alert.ingestedAt || alert.timestamp).toLocaleTimeString("en-US", {
                            hour: "2-digit",
                            minute: "2-digit",
                          })}
                        </span>
                      </div>
                    </td>
                  )}
                  <td className="px-2 py-3">
                    <Link href={`/dashboard/alerts/${alert.id}`}>
                      <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/40 group-hover:text-foreground/60 transition-colors" />
                    </Link>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={Math.max(2, visibleColumns.length + 1)} className="px-4 py-12 text-center">
                    <p className="text-sm text-muted-foreground">No alerts match your filters</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="flex items-center justify-between">
        <p className="text-[11px] text-muted-foreground">
          Showing {filtered.length} of {initialAlerts.length} alerts
        </p>
      </div>
    </div>
  )
}
