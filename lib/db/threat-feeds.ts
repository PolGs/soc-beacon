import { getDb, persistDb } from "./index"
import type { ThreatFeed } from "../types"
import { nanoid } from "nanoid"

function stmtToObjects(db: Awaited<ReturnType<typeof getDb>>, sql: string, params: unknown[] = []): Record<string, unknown>[] {
  const stmt = db.prepare(sql)
  if (params.length) stmt.bind(params)
  const results: Record<string, unknown>[] = []
  while (stmt.step()) {
    results.push(stmt.getAsObject())
  }
  stmt.free()
  return results
}

export async function getThreatFeeds(): Promise<ThreatFeed[]> {
  const db = await getDb()
  return stmtToObjects(db, "SELECT * FROM threat_feeds ORDER BY name").map((r) => ({
    id: r.id as string,
    name: r.name as string,
    url: r.url as string,
    apiKey: (r.api_key as string) || "",
    enabled: !!(r.enabled as number),
  }))
}

export async function addThreatFeed(data: { name: string; url: string; apiKey?: string }): Promise<string> {
  const db = await getDb()
  const id = nanoid()
  db.run("INSERT INTO threat_feeds (id, name, url, api_key, enabled) VALUES (?, ?, ?, ?, 1)", [
    id, data.name, data.url, data.apiKey || "",
  ])
  persistDb()
  return id
}

export async function removeThreatFeed(id: string): Promise<void> {
  const db = await getDb()
  db.run("DELETE FROM threat_feeds WHERE id = ?", [id])
  persistDb()
}

export async function toggleThreatFeed(id: string, enabled: boolean): Promise<void> {
  const db = await getDb()
  db.run("UPDATE threat_feeds SET enabled = ? WHERE id = ?", [enabled ? 1 : 0, id])
  persistDb()
}

export async function updateThreatFeedApiKey(id: string, apiKey: string): Promise<void> {
  const db = await getDb()
  db.run("UPDATE threat_feeds SET api_key = ? WHERE id = ?", [apiKey, id])
  persistDb()
}
