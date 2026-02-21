import { ShieldAlert, ShieldCheck, Search, AlertTriangle } from "lucide-react"

interface OverviewStatsProps {
  counts: {
    severity: Record<string, number>
    status: Record<string, number>
    total: number
  }
}

export function OverviewStats({ counts }: OverviewStatsProps) {
  const critHigh = (counts.severity.critical || 0) + (counts.severity.high || 0)

  const stats = [
    {
      label: "Total Alerts",
      value: counts.total,
      sub: "Last 24 hours",
      icon: ShieldAlert,
      iconClass: "text-muted-foreground/60",
      accentClass: "",
    },
    {
      label: "Critical / High",
      value: critHigh,
      sub: `${counts.severity.critical || 0} critical, ${counts.severity.high || 0} high`,
      icon: AlertTriangle,
      iconClass: critHigh > 0 ? "text-[hsl(var(--severity-critical))]" : "text-muted-foreground/60",
      accentClass: critHigh > 0 ? "border-l-2 border-l-[hsl(var(--severity-critical))]/50" : "",
    },
    {
      label: "In Progress",
      value: counts.status.in_progress || 0,
      sub: `${counts.status.unassigned || 0} unassigned`,
      icon: Search,
      iconClass: (counts.status.in_progress || 0) > 0 ? "text-[hsl(var(--status-investigating))]" : "text-muted-foreground/60",
      accentClass: "",
    },
    {
      label: "Resolved",
      value: counts.status.resolved || 0,
      sub: `${counts.status.in_progress || 0} active incidents`,
      icon: ShieldCheck,
      iconClass: "text-[hsl(var(--status-resolved))]/70",
      accentClass: "",
    },
  ]

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {stats.map((stat) => (
        <div
          key={stat.label}
          className={`glass rounded-lg p-4 flex flex-col gap-3 ${stat.accentClass}`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[11px] uppercase tracking-wider text-muted-foreground font-medium">
              {stat.label}
            </span>
            <stat.icon className={`w-4 h-4 ${stat.iconClass}`} />
          </div>
          <div>
            <span className="text-2xl font-semibold text-foreground tabular-nums">
              {stat.value}
            </span>
            <p className="text-[11px] text-muted-foreground mt-1">{stat.sub}</p>
          </div>
        </div>
      ))}
    </div>
  )
}
