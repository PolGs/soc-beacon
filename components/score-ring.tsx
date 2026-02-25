"use client"

import { cn } from "@/lib/utils"

interface ScoreRingProps {
  label: string
  score: number
  size?: number
  className?: string
  showLabel?: boolean
  sublabel?: string
}

export function getScoreColor(score: number): string {
  if (score >= 85) return "hsl(0 78% 52%)"
  if (score >= 60) return "hsl(45 93% 47%)"
  return "hsl(142 71% 45%)"
}

export function getScoreLabel(score: number): string {
  if (score >= 85) return "Critical"
  if (score >= 60) return "Suspicious"
  return "Low Risk"
}

export function ScoreRing({ label, score, size = 48, className, showLabel = true, sublabel }: ScoreRingProps) {
  const normalized = Math.max(0, Math.min(100, Math.round(score)))
  const stroke = Math.max(3, Math.floor(size / 12))
  const radius = (size - stroke) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (normalized / 100) * circumference
  const color = getScoreColor(normalized)
  const fontSize = size >= 80 ? "text-lg" : size >= 60 ? "text-sm" : "text-[10px]"

  return (
    <div className={cn("inline-flex flex-col items-center gap-1", className)}>
      <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
        {/* Background glow */}
        <div
          className="absolute inset-0 rounded-full opacity-10 blur-md"
          style={{ backgroundColor: color }}
        />
        <svg width={size} height={size} className="-rotate-90" style={{ position: "relative" }}>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="hsl(var(--border))"
            strokeWidth={stroke}
            fill="none"
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={color}
            strokeWidth={stroke}
            fill="none"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ transition: "stroke-dashoffset 0.6s ease, stroke 0.4s ease" }}
          />
        </svg>
        <span
          className={cn("absolute font-mono font-semibold tabular-nums", fontSize)}
          style={{ color }}
        >
          {normalized}
        </span>
      </div>
      {showLabel && (
        <div className="flex flex-col items-center">
          <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium leading-tight">
            {label}
          </span>
          {sublabel && (
            <span className="text-[9px] text-muted-foreground/60 leading-tight">{sublabel}</span>
          )}
        </div>
      )}
    </div>
  )
}

interface CombinedScoreDisplayProps {
  aiScore: number
  heuristicsScore: number
  className?: string
}

export function CombinedScoreDisplay({ aiScore, heuristicsScore, className }: CombinedScoreDisplayProps) {
  const combined = Math.round((aiScore + heuristicsScore) / 2)
  const color = getScoreColor(combined)
  const riskLabel = getScoreLabel(combined)

  return (
    <div className={cn("flex flex-col items-center gap-3", className)}>
      {/* Big combined ring */}
      <div className="flex flex-col items-center gap-1.5">
        <ScoreRing label="Combined Risk" score={combined} size={96} sublabel={riskLabel} />
      </div>

      {/* Divider */}
      <div className="flex items-center gap-2 w-full max-w-[140px]">
        <div className="flex-1 h-px bg-border/30" />
        <span className="text-[9px] uppercase tracking-wider text-muted-foreground/40 shrink-0">breakdown</span>
        <div className="flex-1 h-px bg-border/30" />
      </div>

      {/* Two smaller rings */}
      <div className="flex items-center gap-4">
        <ScoreRing label="AI" score={aiScore} size={52} sublabel="LLM" />
        <ScoreRing label="Heuristics" score={heuristicsScore} size={52} sublabel="Rules" />
      </div>
    </div>
  )
}
