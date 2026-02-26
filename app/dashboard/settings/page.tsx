import { SettingsView } from "@/components/settings-view"
import { getAllSettings } from "@/lib/db/settings"
import { getThreatFeeds } from "@/lib/db/threat-feeds"
import { getYaraRules } from "@/lib/db/yara-rules"
import { requireAuth } from "@/lib/auth"
import { listUsers } from "@/lib/db/users"

export default async function SettingsPage() {
  const session = await requireAuth()
  const isAdmin = session.role === "admin"

  const settings = await getAllSettings()
  const feeds = await getThreatFeeds()
  const yaraRules = await getYaraRules()
  const users = isAdmin ? await listUsers() : []

  const safeSettings = structuredClone(settings) as Record<string, unknown>
  if (!isAdmin) {
    const api = (safeSettings.api || {}) as Record<string, unknown>
    const llm = (safeSettings.llm || {}) as Record<string, unknown>
    safeSettings.api = { ...api, apiKey: "" }
    safeSettings.llm = { ...llm, apiKey: "" }
  }

  const safeFeeds = isAdmin ? feeds : feeds.map((f) => ({ ...f, apiKey: "" }))

  return (
    <div className="p-6 flex flex-col gap-6">
      <div>
        <h1 className="text-lg font-semibold text-foreground">Settings</h1>
        <p className="text-xs text-muted-foreground mt-0.5">
          Configure SOC Beacon integrations, ingestion, and AI enrichment
        </p>
      </div>
      <SettingsView
        initialSettings={safeSettings}
        initialFeeds={safeFeeds}
        initialYaraRules={yaraRules}
        initialUsers={users}
        currentUser={session.user}
        currentRole={session.role || "analyst"}
      />
    </div>
  )
}
