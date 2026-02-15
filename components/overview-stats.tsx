import { severityCounts, statusCounts, alerts } from "@/lib/mock-data"
import { ShieldAlert, ShieldCheck, Search, AlertTriangle } from "lucide-react"

const stats = [
  {
    label: "Total Alerts",
    value: alerts.length,
    sub: "Last 24 hours",
    icon: ShieldAlert,
  },
  {
    label: "Critical / High",
    value: severityCounts.critical + severityCounts.high,
    sub: `${severityCounts.critical} critical, ${severityCounts.high} high`,
    icon: AlertTriangle,
  },
  {
    label: "Investigating",
    value: statusCounts.investigating,
    sub: `${statusCounts.new} new pending`,
    icon: Search,
  },
  {
    label: "Resolved",
    value: statusCounts.resolved + statusCounts.false_positive,
    sub: `${statusCounts.false_positive} false positive`,
    icon: ShieldCheck,
  },
]

export function OverviewStats() {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {stats.map((stat) => (
        <div
          key={stat.label}
          className="glass rounded-lg p-4 flex flex-col gap-3"
        >
          <div className="flex items-center justify-between">
            <span className="text-[11px] uppercase tracking-wider text-muted-foreground font-medium">
              {stat.label}
            </span>
            <stat.icon className="w-4 h-4 text-muted-foreground/60" />
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
