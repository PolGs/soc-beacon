import { cn } from "@/lib/utils"
import type { IncidentStatus } from "@/lib/types"

const statusConfig: Record<IncidentStatus, { label: string; className: string }> = {
  unassigned: {
    label: "Unassigned",
    className: "border-[hsl(var(--status-new))]/40 text-[hsl(var(--status-new))] bg-[hsl(var(--status-new))]/10",
  },
  in_progress: {
    label: "In Progress",
    className: "border-[hsl(var(--status-investigating))]/40 text-[hsl(var(--status-investigating))] bg-[hsl(var(--status-investigating))]/10",
  },
  resolved: {
    label: "Resolved",
    className: "border-[hsl(var(--status-resolved))]/40 text-[hsl(var(--status-resolved))] bg-[hsl(var(--status-resolved))]/10",
  },
}

export function StatusBadge({ status }: { status: IncidentStatus }) {
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
