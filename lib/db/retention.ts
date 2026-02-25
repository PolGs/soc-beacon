import { getDb, persistDb } from "./index"

export async function runRetentionCleanup(retentionDays: number): Promise<void> {
  const days = Math.max(1, retentionDays)
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString()

  const db = await getDb()
  db.run("DELETE FROM alert_enrichments WHERE alert_id IN (SELECT id FROM alerts WHERE timestamp < ?)", [cutoff])
  db.run("DELETE FROM alerts WHERE timestamp < ?", [cutoff])
  db.run("DELETE FROM logs WHERE timestamp < ?", [cutoff])
  persistDb()
}
