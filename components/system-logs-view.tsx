"use client"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Loader2, RefreshCw, Trash2 } from "lucide-react"

interface SystemLogEntry {
  id: string
  ts: string
  level: "debug" | "info" | "warn" | "error"
  source: string
  message: string
  meta?: Record<string, unknown>
}

export function SystemLogsView() {
  const [logs, setLogs] = useState<SystemLogEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [clearing, setClearing] = useState(false)
  const [autoRefresh, setAutoRefresh] = useState(true)

  const loadLogs = async () => {
    setLoading(true)
    try {
      const res = await fetch("/api/v1/system-logs?limit=300", { cache: "no-store" })
      const data = await res.json()
      if (res.ok) setLogs(data.logs || [])
    } finally {
      setLoading(false)
    }
  }

  const clearLogs = async () => {
    setClearing(true)
    try {
      await fetch("/api/v1/system-logs", { method: "DELETE" })
      setLogs([])
    } finally {
      setClearing(false)
    }
  }

  useEffect(() => {
    loadLogs()
  }, [])

  useEffect(() => {
    if (!autoRefresh) return
    const id = setInterval(() => {
      loadLogs()
    }, 5000)
    return () => clearInterval(id)
  }, [autoRefresh])

  return (
    <div className="glass rounded-lg p-5 flex flex-col gap-4">
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="text-sm font-medium text-foreground">System Logs</h2>
          <p className="text-[11px] text-muted-foreground">Runtime logs for Sigma, LLM, threat intel, and ingestion.</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className="h-8 rounded-md border border-border/50 px-2 text-[11px] text-muted-foreground hover:text-foreground hover:border-foreground/30 transition-colors"
          >
            {autoRefresh ? "Auto-refresh: On" : "Auto-refresh: Off"}
          </button>
          <Button size="sm" variant="ghost" className="h-8 px-2" onClick={loadLogs} disabled={loading}>
            {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
          </Button>
          <Button size="sm" variant="ghost" className="h-8 px-2" onClick={clearLogs} disabled={clearing}>
            {clearing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
          </Button>
        </div>
      </div>

      <div className="rounded-md border border-border/40 overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="text-[11px]">Time</TableHead>
              <TableHead className="text-[11px]">Level</TableHead>
              <TableHead className="text-[11px]">Source</TableHead>
              <TableHead className="text-[11px]">Message</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {logs.length === 0 && (
              <TableRow>
                <TableCell colSpan={4} className="text-xs text-muted-foreground text-center py-8">
                  No system logs yet.
                </TableCell>
              </TableRow>
            )}
            {logs.map((log) => (
              <TableRow key={log.id}>
                <TableCell className="text-[11px] font-mono text-muted-foreground whitespace-nowrap">
                  {new Date(log.ts).toLocaleString()}
                </TableCell>
                <TableCell className="text-[11px] uppercase font-mono">
                  <span
                    className={
                      log.level === "error"
                        ? "text-red-400"
                        : log.level === "warn"
                          ? "text-amber-400"
                          : log.level === "debug"
                            ? "text-foreground/60"
                            : "text-foreground/80"
                    }
                  >
                    {log.level}
                  </span>
                </TableCell>
                <TableCell className="text-[11px] text-foreground/70">{log.source}</TableCell>
                <TableCell className="text-[11px] text-foreground/80">
                  <div className="flex flex-col gap-1">
                    <span>{log.message}</span>
                    {log.meta && (
                      <pre className="text-[10px] font-mono text-muted-foreground whitespace-pre-wrap break-all">
                        {JSON.stringify(log.meta, null, 2)}
                      </pre>
                    )}
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  )
}
