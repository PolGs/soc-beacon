"use client"

import { cn } from "@/lib/utils"

interface ScoreRingProps {
  label: string
  score: number
  size?: number
  className?: string
}

function getScoreColor(score: number): string {
  if (score >= 85) return "hsl(0 78% 52%)"
  if (score >= 60) return "hsl(45 93% 47%)"
  return "hsl(142 71% 45%)"
}

export function ScoreRing({ label, score, size = 48, className }: ScoreRingProps) {
  const normalized = Math.max(0, Math.min(100, Math.round(score)))
  const stroke = Math.max(3, Math.floor(size / 12))
  const radius = (size - stroke) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (normalized / 100) * circumference

  return (
    <div className={cn("inline-flex items-center gap-2", className)}>
      <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle cx={size / 2} cy={size / 2} r={radius} stroke="hsl(var(--border))" strokeWidth={stroke} fill="none" />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={getScoreColor(normalized)}
            strokeWidth={stroke}
            fill="none"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
          />
        </svg>
        <span className="absolute text-[10px] font-mono tabular-nums text-foreground">{normalized}</span>
      </div>
      <div className="flex flex-col">
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</span>
        <span className="text-[11px] text-foreground/80">Score</span>
      </div>
    </div>
  )
}
