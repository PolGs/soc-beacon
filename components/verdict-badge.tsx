import { cn } from "@/lib/utils"
import type { AlertVerdict } from "@/lib/types"

const verdictConfig: Record<AlertVerdict, { label: string; className: string }> = {
  malicious: {
    label: "Malicious",
    className: "border-[hsl(var(--severity-critical))]/40 text-[hsl(var(--severity-critical))] bg-[hsl(var(--severity-critical))]/10",
  },
  suspicious: {
    label: "Suspicious",
    className: "border-[hsl(var(--severity-medium))]/40 text-[hsl(var(--severity-medium))] bg-[hsl(var(--severity-medium))]/10",
  },
  false_positive: {
    label: "False Positive",
    className: "border-foreground/20 text-muted-foreground bg-foreground/5",
  },
}

export function VerdictBadge({ verdict }: { verdict: AlertVerdict }) {
  const config = verdictConfig[verdict]
  return (
    <span
      className={cn(
        "inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-medium leading-none",
        config.className
      )}
    >
      {config.label}
    </span>
  )
}
