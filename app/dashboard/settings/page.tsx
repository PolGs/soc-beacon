import { SettingsView } from "@/components/settings-view"
import { getAllSettings } from "@/lib/db/settings"
import { getThreatFeeds } from "@/lib/db/threat-feeds"
import { getYaraRules } from "@/lib/db/yara-rules"

export default async function SettingsPage() {
  const settings = await getAllSettings()
  const feeds = await getThreatFeeds()
  const yaraRules = await getYaraRules()

  return (
    <div className="p-6 flex flex-col gap-6">
      <div>
        <h1 className="text-lg font-semibold text-foreground">Settings</h1>
        <p className="text-xs text-muted-foreground mt-0.5">
          Configure SOC Beacon integrations, ingestion, and AI enrichment
        </p>
      </div>
      <SettingsView
        initialSettings={settings}
        initialFeeds={feeds}
        initialYaraRules={yaraRules}
      />
    </div>
  )
}
