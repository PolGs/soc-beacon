"use client"

import { useState, useEffect, useRef } from "react"
import type { LogEntry, Severity } from "@/lib/types"
import { SeverityBadge } from "@/components/severity-badge"
import { cn } from "@/lib/utils"
import { Search, Pause, Play, ArrowDown, Filter, Upload } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { LogUploadDialog } from "@/components/log-upload-dialog"

const severityFilters: { key: Severity | "all"; label: string }[] = [
  { key: "all", label: "All" },
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "low", label: "Low" },
  { key: "info", label: "Info" },
]

interface LogExplorerProps {
  initialLogs: LogEntry[]
  sources: string[]
  stats: { total: number; parsed: number; severityCounts: Record<string, number> }
}

export function LogExplorer({ initialLogs, sources, stats }: LogExplorerProps) {
  const [searchQuery, setSearchQuery] = useState("")
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all")
  const [sourceFilter, setSourceFilter] = useState("All")
  const [isLive, setIsLive] = useState(true)
  const [showScrollDown, setShowScrollDown] = useState(false)
  const [uploadOpen, setUploadOpen] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)

  const sourceFilters = ["All", ...sources]

  const filtered = initialLogs.filter((log) => {
    if (severityFilter !== "all" && log.severity !== severityFilter) return false
    if (sourceFilter !== "All" && !log.source.toLowerCase().includes(sourceFilter.toLowerCase()))
      return false
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      return (
        log.message.toLowerCase().includes(q) ||
        log.source.toLowerCase().includes(q) ||
        log.id.toLowerCase().includes(q)
      )
    }
    return true
  })

  const handleScroll = () => {
    if (!scrollRef.current) return
    const { scrollTop, scrollHeight, clientHeight } = scrollRef.current
    setShowScrollDown(scrollHeight - scrollTop - clientHeight > 100)
  }

  const scrollToBottom = () => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }

  useEffect(() => {
    if (isLive) {
      scrollToBottom()
    }
  }, [isLive, filtered.length])

  return (
    <div className="flex flex-col gap-4">
      {/* Controls bar */}
      <div className="flex flex-col gap-3">
        {/* Top row: search + live toggle + upload */}
        <div className="flex items-center gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <Input
              placeholder="Search logs, IPs, messages..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 h-8 text-xs bg-card/60 border-border/50 placeholder:text-muted-foreground/40 font-mono"
            />
          </div>

          <Button
            variant="ghost"
            size="sm"
            className={cn(
              "h-8 px-3 text-xs gap-1.5",
              isLive
                ? "text-foreground bg-foreground/10"
                : "text-muted-foreground hover:text-foreground"
            )}
            onClick={() => setIsLive(!isLive)}
          >
            {isLive ? (
              <>
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                Live
                <Pause className="w-3 h-3" />
              </>
            ) : (
              <>
                <span className="w-1.5 h-1.5 rounded-full bg-muted-foreground" />
                Paused
                <Play className="w-3 h-3" />
              </>
            )}
          </Button>

          <Button
            variant="ghost"
            size="sm"
            className="h-8 px-3 text-xs gap-1.5 text-muted-foreground hover:text-foreground"
            onClick={() => setUploadOpen(true)}
          >
            <Upload className="w-3 h-3" />
            Upload
          </Button>
        </div>

        {/* Severity filters */}
        <div className="flex items-center gap-2 flex-wrap">
          {severityFilters.map((f) => {
            const count = f.key === "all" ? stats.total : stats.severityCounts[f.key] || 0
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

          <span className="w-px h-5 bg-border/50 mx-1" />

          {/* Source filter dropdown */}
          <div className="flex items-center gap-1 px-2 py-1 rounded-md glass-subtle">
            <Filter className="w-3 h-3 text-muted-foreground" />
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="bg-transparent text-[11px] text-muted-foreground focus:text-foreground outline-none cursor-pointer"
            >
              {sourceFilters.map((s) => (
                <option key={s} value={s} className="bg-card text-foreground">
                  {s}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Log stream */}
      <div className="glass rounded-lg overflow-hidden relative">
        {/* Header */}
        <div className="flex items-center border-b border-border/40 bg-muted/20 px-4 py-2">
          <span className="text-[11px] font-medium text-muted-foreground w-20">Time</span>
          <span className="text-[11px] font-medium text-muted-foreground w-14">Sev.</span>
          <span className="text-[11px] font-medium text-muted-foreground w-36">Source</span>
          <span className="text-[11px] font-medium text-muted-foreground flex-1">Message</span>
        </div>

        {/* Scrollable log area */}
        <div
          ref={scrollRef}
          onScroll={handleScroll}
          className="h-[520px] overflow-y-auto"
        >
          {filtered.map((log) => (
            <div
              key={log.id}
              className="flex items-start px-4 py-2 border-b border-border/10 hover:bg-foreground/[0.02] transition-colors group"
            >
              <span className="text-[11px] font-mono text-muted-foreground tabular-nums w-20 shrink-0 pt-0.5">
                {new Date(log.timestamp).toLocaleTimeString("en-US", {
                  hour: "2-digit",
                  minute: "2-digit",
                  second: "2-digit",
                })}
              </span>
              <span className="w-14 shrink-0 pt-0.5">
                <SeverityBadge severity={log.severity} />
              </span>
              <span className="text-[11px] font-mono text-foreground/50 w-36 shrink-0 pt-0.5 truncate">
                {log.source}
              </span>
              <span className="text-[11px] font-mono text-foreground/70 flex-1 leading-relaxed break-all">
                {searchQuery ? highlightMatch(log.message, searchQuery) : log.message}
              </span>
            </div>
          ))}
          {filtered.length === 0 && (
            <div className="flex items-center justify-center py-16">
              <p className="text-sm text-muted-foreground">No logs match your filters</p>
            </div>
          )}
        </div>

        {/* Scroll to bottom indicator */}
        {showScrollDown && (
          <button
            onClick={scrollToBottom}
            className="absolute bottom-3 right-3 flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-card/90 backdrop-blur-lg border border-border/50 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            <ArrowDown className="w-3 h-3" />
            Latest
          </button>
        )}
      </div>

      {/* Footer stats */}
      <div className="flex items-center justify-between">
        <p className="text-[11px] text-muted-foreground">
          Showing {filtered.length} of {stats.total} log entries
        </p>
        <div className="flex items-center gap-4">
          <span className="text-[11px] text-muted-foreground">
            Parsed:{" "}
            <span className="font-mono text-foreground/70 tabular-nums">
              {stats.parsed}/{stats.total}
            </span>
          </span>
        </div>
      </div>

      {/* Upload dialog */}
      <LogUploadDialog open={uploadOpen} onOpenChange={setUploadOpen} />
    </div>
  )
}

function highlightMatch(text: string, query: string) {
  if (!query) return text
  const regex = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`, "gi")
  const parts = text.split(regex)
  return parts.map((part, i) =>
    regex.test(part) ? (
      <span key={i} className="bg-foreground/20 text-foreground rounded-sm px-0.5">
        {part}
      </span>
    ) : (
      part
    )
  )
}
