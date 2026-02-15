"use client"

import { useState } from "react"
import Link from "next/link"
import { alerts, type Severity } from "@/lib/mock-data"
import { SeverityBadge } from "@/components/severity-badge"
import { StatusBadge } from "@/components/status-badge"
import { cn } from "@/lib/utils"
import { Search, Filter, ChevronRight } from "lucide-react"
import { Input } from "@/components/ui/input"

const severityFilters: { key: Severity | "all"; label: string }[] = [
  { key: "all", label: "All" },
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "low", label: "Low" },
  { key: "info", label: "Info" },
]

const statusFilters = ["all", "new", "investigating", "resolved", "false_positive"] as const

export function AlertsView() {
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all")
  const [statusFilter, setStatusFilter] = useState<string>("all")
  const [searchQuery, setSearchQuery] = useState("")

  const filtered = alerts.filter((a) => {
    if (severityFilter !== "all" && a.severity !== severityFilter) return false
    if (statusFilter !== "all" && a.status !== statusFilter) return false
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

  const severityCounts = alerts.reduce(
    (acc, a) => {
      acc[a.severity] = (acc[a.severity] || 0) + 1
      return acc
    },
    {} as Record<string, number>
  )

  return (
    <div className="flex flex-col gap-4">
      {/* Severity filter pills */}
      <div className="flex flex-wrap items-center gap-2">
        {severityFilters.map((f) => {
          const count = f.key === "all" ? alerts.length : severityCounts[f.key] || 0
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

      {/* Search and status filter */}
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
        <div className="flex items-center gap-1 px-2 py-1 rounded-md glass-subtle">
          <Filter className="w-3 h-3 text-muted-foreground" />
          {statusFilters.map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={cn(
                "px-2 py-0.5 text-[11px] rounded transition-colors capitalize",
                statusFilter === s
                  ? "bg-foreground/10 text-foreground"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              {s === "false_positive" ? "FP" : s}
            </button>
          ))}
        </div>
      </div>

      {/* Alerts table */}
      <div className="glass rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border/40 bg-muted/20">
                <th className="text-[11px] font-medium text-muted-foreground text-left px-4 py-2.5 w-16">Sev.</th>
                <th className="text-[11px] font-medium text-muted-foreground text-left px-4 py-2.5 w-20">ID</th>
                <th className="text-[11px] font-medium text-muted-foreground text-left px-4 py-2.5">Alert</th>
                <th className="text-[11px] font-medium text-muted-foreground text-left px-4 py-2.5 hidden md:table-cell">Source</th>
                <th className="text-[11px] font-medium text-muted-foreground text-left px-4 py-2.5 hidden lg:table-cell">MITRE Tactic</th>
                <th className="text-[11px] font-medium text-muted-foreground text-left px-4 py-2.5 hidden md:table-cell">Status</th>
                <th className="text-[11px] font-medium text-muted-foreground text-left px-4 py-2.5 hidden lg:table-cell">Confidence</th>
                <th className="text-[11px] font-medium text-muted-foreground text-left px-4 py-2.5">Time</th>
                <th className="w-8" />
              </tr>
            </thead>
            <tbody>
              {filtered.map((alert) => (
                <tr
                  key={alert.id}
                  className="border-b border-border/20 last:border-0 hover:bg-foreground/[0.02] transition-colors group"
                >
                  <td className="px-4 py-3">
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-[11px] font-mono text-muted-foreground">{alert.id}</span>
                  </td>
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
                  <td className="px-4 py-3 hidden md:table-cell">
                    <div className="flex flex-col">
                      <span className="text-[11px] font-mono text-foreground/70">{alert.source}</span>
                      <span className="text-[10px] text-muted-foreground font-mono">{alert.sourceIp}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 hidden lg:table-cell">
                    <span className="text-[11px] text-muted-foreground">{alert.mitreTactic}</span>
                  </td>
                  <td className="px-4 py-3 hidden md:table-cell">
                    <StatusBadge status={alert.status} />
                  </td>
                  <td className="px-4 py-3 hidden lg:table-cell">
                    <div className="flex items-center gap-1.5">
                      <div className="w-12 h-1 rounded-full bg-foreground/10 overflow-hidden">
                        <div
                          className="h-full rounded-full bg-foreground/60"
                          style={{ width: `${alert.enrichment.confidence}%` }}
                        />
                      </div>
                      <span className="text-[10px] text-muted-foreground tabular-nums">
                        {alert.enrichment.confidence}%
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-[11px] text-muted-foreground tabular-nums whitespace-nowrap">
                      {new Date(alert.timestamp).toLocaleTimeString("en-US", {
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </span>
                  </td>
                  <td className="px-2 py-3">
                    <Link href={`/dashboard/alerts/${alert.id}`}>
                      <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/40 group-hover:text-foreground/60 transition-colors" />
                    </Link>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-4 py-12 text-center">
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
          Showing {filtered.length} of {alerts.length} alerts
        </p>
      </div>
    </div>
  )
}
