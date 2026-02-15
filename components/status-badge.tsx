import { cn } from "@/lib/utils"

type AlertStatus = "new" | "investigating" | "resolved" | "false_positive"

const statusConfig: Record<AlertStatus, { label: string; className: string }> = {
  new: {
    label: "New",
    className: "border-foreground/40 text-foreground/80",
  },
  investigating: {
    label: "Investigating",
    className: "border-foreground/25 text-foreground/60",
  },
  resolved: {
    label: "Resolved",
    className: "border-foreground/15 text-foreground/40",
  },
  false_positive: {
    label: "False Positive",
    className: "border-foreground/10 text-foreground/30",
  },
}

export function StatusBadge({ status }: { status: AlertStatus }) {
  const config = statusConfig[status]
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
