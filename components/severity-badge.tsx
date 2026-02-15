import { cn } from "@/lib/utils"
import type { Severity } from "@/lib/mock-data"

const severityConfig: Record<Severity, { label: string; className: string }> = {
  critical: {
    label: "CRIT",
    className: "bg-foreground/90 text-background",
  },
  high: {
    label: "HIGH",
    className: "bg-foreground/50 text-foreground",
  },
  medium: {
    label: "MED",
    className: "bg-foreground/20 text-foreground/80",
  },
  low: {
    label: "LOW",
    className: "bg-foreground/10 text-foreground/60",
  },
  info: {
    label: "INFO",
    className: "bg-foreground/5 text-foreground/40",
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
