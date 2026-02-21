"use client"

import { useState, useCallback } from "react"
import { Upload, FileText, Loader2, X, CheckCircle } from "lucide-react"
import { useRouter } from "next/navigation"

interface LogUploadDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function LogUploadDialog({ open, onOpenChange }: LogUploadDialogProps) {
  const [dragOver, setDragOver] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [result, setResult] = useState<{ logCount: number; alertCount: number } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const router = useRouter()

  const handleFile = useCallback(async (file: File) => {
    setUploading(true)
    setError(null)
    setResult(null)

    try {
      const formData = new FormData()
      formData.append("file", file)

      const res = await fetch("/api/v1/upload", { method: "POST", body: formData })
      const data = await res.json()

      if (!res.ok) {
        setError(data.error || "Upload failed")
      } else {
        setResult({ logCount: data.logCount, alertCount: data.alertCount })
        router.refresh()
      }
    } catch {
      setError("Network error during upload")
    } finally {
      setUploading(false)
    }
  }, [router])

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      setDragOver(false)
      const file = e.dataTransfer.files[0]
      if (file) handleFile(file)
    },
    [handleFile]
  )

  const handleFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0]
      if (file) handleFile(file)
    },
    [handleFile]
  )

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm">
      <div className="glass rounded-lg w-full max-w-md p-6 border border-border/50 mx-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-medium text-foreground">Upload Log File</h3>
          <button
            onClick={() => {
              onOpenChange(false)
              setResult(null)
              setError(null)
            }}
            className="p-1 rounded hover:bg-foreground/10 transition-colors text-muted-foreground"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="text-[11px] text-muted-foreground mb-4">
          Supports CSV, JSON, NDJSON, and plain text log formats. Logs will be parsed, classified, and alerts generated automatically.
        </p>

        {/* Drop zone */}
        <div
          onDragOver={(e) => {
            e.preventDefault()
            setDragOver(true)
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
            dragOver
              ? "border-foreground/40 bg-foreground/5"
              : "border-border/50 hover:border-foreground/20"
          }`}
        >
          {uploading ? (
            <div className="flex flex-col items-center gap-2">
              <Loader2 className="w-6 h-6 text-muted-foreground animate-spin" />
              <p className="text-xs text-muted-foreground">Processing logs...</p>
            </div>
          ) : result ? (
            <div className="flex flex-col items-center gap-2">
              <CheckCircle className="w-6 h-6 text-foreground/70" />
              <p className="text-xs text-foreground">
                Ingested {result.logCount} logs, generated {result.alertCount} alerts
              </p>
            </div>
          ) : (
            <label className="flex flex-col items-center gap-2 cursor-pointer">
              <Upload className="w-6 h-6 text-muted-foreground" />
              <p className="text-xs text-muted-foreground">
                Drop file here or <span className="text-foreground underline">browse</span>
              </p>
              <p className="text-[10px] text-muted-foreground/60">.csv, .json, .log, .txt</p>
              <input
                type="file"
                accept=".csv,.json,.log,.txt,.ndjson"
                onChange={handleFileSelect}
                className="hidden"
              />
            </label>
          )}
        </div>

        {error && (
          <div className="mt-3 p-2 rounded bg-red-500/10 border border-red-500/20">
            <p className="text-[11px] text-red-400">{error}</p>
          </div>
        )}

        <div className="mt-4 flex items-center gap-2 text-[10px] text-muted-foreground/60">
          <FileText className="w-3 h-3" />
          <span>Files are parsed server-side and never stored as-is</span>
        </div>
      </div>
    </div>
  )
}
