import { OverviewStats } from "@/components/overview-stats"
import { AlertTimeline } from "@/components/alert-timeline"
import { RecentAlerts } from "@/components/recent-alerts"
import { SourceDistribution } from "@/components/source-distribution"
import { MitreHeatmap } from "@/components/mitre-heatmap"
import { SystemStatus } from "@/components/system-status"
import { getAlertCounts, getTimelineData, getSourceDistribution, getTopMitreTechniques, getAlerts } from "@/lib/db/alerts"
import { getAllSettings } from "@/lib/db/settings"

export const dynamic = "force-dynamic"

export default async function DashboardOverview() {
  const [counts, timeline, sources, mitre, recentAlerts, settings] = await Promise.all([
    getAlertCounts(),
    getTimelineData(24),
    getSourceDistribution(),
    getTopMitreTechniques(6),
    getAlerts({ limit: 6 }),
    getAllSettings(),
  ])

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
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-[11px] text-muted-foreground">Live</span>
          </div>
        </div>
      </div>

      {/* Stats */}
      <OverviewStats counts={counts} />

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <AlertTimeline data={timeline} />
        </div>
        <SourceDistribution data={sources} />
      </div>

      {/* Bottom row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <RecentAlerts alerts={recentAlerts} />
        </div>
        <div className="flex flex-col gap-6">
          <MitreHeatmap data={mitre} />
          <SystemStatus settings={settings} />
        </div>
      </div>
    </div>
  )
}
