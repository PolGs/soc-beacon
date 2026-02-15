import Link from "next/link"
import { alerts } from "@/lib/mock-data"
import { SeverityBadge } from "@/components/severity-badge"
import { StatusBadge } from "@/components/status-badge"
import { ArrowRight } from "lucide-react"

export function RecentAlerts() {
  const recentAlerts = alerts.slice(0, 6)

  return (
    <div className="glass rounded-lg">
      <div className="flex items-center justify-between p-4 pb-0">
        <div>
          <h3 className="text-sm font-medium text-foreground">Recent Alerts</h3>
          <p className="text-[11px] text-muted-foreground mt-0.5">Latest security events</p>
        </div>
        <Link
          href="/dashboard/alerts"
          className="text-[11px] text-muted-foreground hover:text-foreground flex items-center gap-1 transition-colors"
        >
          View all <ArrowRight className="w-3 h-3" />
        </Link>
      </div>

      <div className="p-2 pt-3">
        <div className="overflow-hidden rounded-md border border-border/30">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border/30 bg-muted/30">
                <th className="text-[11px] font-medium text-muted-foreground text-left px-3 py-2">Severity</th>
                <th className="text-[11px] font-medium text-muted-foreground text-left px-3 py-2">Alert</th>
                <th className="text-[11px] font-medium text-muted-foreground text-left px-3 py-2 hidden md:table-cell">Source</th>
                <th className="text-[11px] font-medium text-muted-foreground text-left px-3 py-2 hidden lg:table-cell">Status</th>
                <th className="text-[11px] font-medium text-muted-foreground text-left px-3 py-2 hidden md:table-cell">Time</th>
              </tr>
            </thead>
            <tbody>
              {recentAlerts.map((alert) => (
                <tr
                  key={alert.id}
                  className="border-b border-border/20 last:border-0 hover:bg-foreground/[0.02] transition-colors"
                >
                  <td className="px-3 py-2.5">
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td className="px-3 py-2.5">
                    <Link
                      href={`/dashboard/alerts/${alert.id}`}
                      className="text-xs text-foreground/90 hover:text-foreground transition-colors font-medium"
                    >
                      {alert.title}
                    </Link>
                  </td>
                  <td className="px-3 py-2.5 hidden md:table-cell">
                    <span className="text-[11px] text-muted-foreground font-mono">{alert.source}</span>
                  </td>
                  <td className="px-3 py-2.5 hidden lg:table-cell">
                    <StatusBadge status={alert.status} />
                  </td>
                  <td className="px-3 py-2.5 hidden md:table-cell">
                    <span className="text-[11px] text-muted-foreground tabular-nums">
                      {new Date(alert.timestamp).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
