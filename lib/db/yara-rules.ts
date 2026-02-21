import { getDb, persistDb } from "./index"
import type { YaraRule } from "../types"
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

export async function getYaraRules(enabledOnly = false): Promise<YaraRule[]> {
  const db = await getDb()
  const sql = enabledOnly
    ? "SELECT * FROM yara_rules WHERE enabled = 1 ORDER BY name"
    : "SELECT * FROM yara_rules ORDER BY name"
  return stmtToObjects(db, sql).map((r) => ({
    id: r.id as string,
    name: r.name as string,
    content: r.content as string,
    enabled: !!(r.enabled as number),
  }))
}

export async function toggleYaraRule(id: string, enabled: boolean): Promise<void> {
  const db = await getDb()
  db.run("UPDATE yara_rules SET enabled = ?, updated_at = datetime('now') WHERE id = ?", [enabled ? 1 : 0, id])
  persistDb()
}

export async function upsertYaraRule(data: { name: string; content: string; enabled?: boolean }): Promise<string> {
  const db = await getDb()
  const existing = stmtToObjects(db, "SELECT id FROM yara_rules WHERE name = ?", [data.name])
  if (existing.length > 0) {
    const id = existing[0].id as string
    db.run("UPDATE yara_rules SET content = ?, enabled = ?, updated_at = datetime('now') WHERE id = ?", [
      data.content, data.enabled !== false ? 1 : 0, id,
    ])
    persistDb()
    return id
  }
  const id = nanoid()
  db.run("INSERT INTO yara_rules (id, name, content, enabled) VALUES (?, ?, ?, ?)", [
    id, data.name, data.content, data.enabled !== false ? 1 : 0,
  ])
  persistDb()
  return id
}

export async function deleteYaraRule(id: string): Promise<void> {
  const db = await getDb()
  db.run("DELETE FROM yara_rules WHERE id = ?", [id])
  persistDb()
}
