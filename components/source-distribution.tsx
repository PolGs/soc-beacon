"use client"

import { sourceDistribution } from "@/lib/mock-data"

export function SourceDistribution() {
  const total = sourceDistribution.reduce((acc, s) => acc + s.value, 0)

  return (
    <div className="glass rounded-lg p-4">
      <div className="mb-4">
        <h3 className="text-sm font-medium text-foreground">Log Sources</h3>
        <p className="text-[11px] text-muted-foreground mt-0.5">Distribution by source type</p>
      </div>

      <div className="flex flex-col gap-3">
        {sourceDistribution.map((source, i) => {
          const pct = Math.round((source.value / total) * 100)
          const opacity = 1 - i * 0.14
          return (
            <div key={source.name} className="flex flex-col gap-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs text-foreground/80">{source.name}</span>
                <span className="text-[11px] text-muted-foreground tabular-nums">{pct}%</span>
              </div>
              <div className="h-1.5 rounded-full bg-foreground/5 overflow-hidden">
                <div
                  className="h-full rounded-full bg-foreground transition-all duration-500"
                  style={{ width: `${pct}%`, opacity }}
                />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
