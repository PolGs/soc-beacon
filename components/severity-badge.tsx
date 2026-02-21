import { cn } from "@/lib/utils"
import type { Severity } from "@/lib/types"

const severityConfig: Record<Severity, { label: string; className: string }> = {
  critical: {
    label: "CRIT",
    className: "bg-[hsl(var(--severity-critical))] text-white",
  },
  high: {
    label: "HIGH",
    className: "bg-[hsl(var(--severity-high))]/90 text-white",
  },
  medium: {
    label: "MED",
    className: "bg-[hsl(var(--severity-medium))]/80 text-black",
  },
  low: {
    label: "LOW",
    className: "bg-[hsl(var(--severity-low))]/20 text-[hsl(var(--severity-low))]",
  },
  info: {
    label: "INFO",
    className: "bg-foreground/5 text-muted-foreground",
  },
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const config = severityConfig[severity]
  return (
    <span
      className={cn(
        "inline-flex items-center justify-center px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold tracking-wider leading-none",
        config.className
      )}
    >
      {config.label}
    </span>
  )
}
