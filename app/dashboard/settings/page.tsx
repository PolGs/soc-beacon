import { SettingsView } from "@/components/settings-view"

export default function SettingsPage() {
  return (
    <div className="p-6 flex flex-col gap-6">
      <div>
        <h1 className="text-lg font-semibold text-foreground">Settings</h1>
        <p className="text-xs text-muted-foreground mt-0.5">
          Configure SOC Beacon integrations, ingestion, and AI enrichment
        </p>
      </div>
      <SettingsView />
    </div>
  )
}
