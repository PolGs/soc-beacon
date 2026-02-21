import { AlertsView } from "@/components/alerts-view"
import { getAlerts } from "@/lib/db/alerts"

export const dynamic = "force-dynamic"

export default async function AlertsPage() {
  const alerts = await getAlerts({ limit: 200 })

  return (
    <div className="p-6 flex flex-col gap-6">
      <div>
        <h1 className="text-lg font-semibold text-foreground">Alerts</h1>
        <p className="text-xs text-muted-foreground mt-0.5">
          Security alerts classified by severity with AI enrichment
        </p>
      </div>
      <AlertsView initialAlerts={alerts} />
    </div>
  )
}
