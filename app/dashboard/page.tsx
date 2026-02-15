import { OverviewStats } from "@/components/overview-stats"
import { AlertTimeline } from "@/components/alert-timeline"
import { RecentAlerts } from "@/components/recent-alerts"
import { SourceDistribution } from "@/components/source-distribution"
import { MitreHeatmap } from "@/components/mitre-heatmap"
import { SystemStatus } from "@/components/system-status"

export default function DashboardOverview() {
  return (
    <div className="p-6 flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-foreground">Overview</h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Real-time security posture and threat landscape
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md glass-subtle">
            <span className="w-1.5 h-1.5 rounded-full bg-foreground animate-pulse" />
            <span className="text-[11px] text-muted-foreground">Live</span>
          </div>
        </div>
      </div>

      {/* Stats */}
      <OverviewStats />

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <AlertTimeline />
        </div>
        <SourceDistribution />
      </div>

      {/* Bottom row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <RecentAlerts />
        </div>
        <div className="flex flex-col gap-6">
          <MitreHeatmap />
          <SystemStatus />
        </div>
      </div>
    </div>
  )
}
