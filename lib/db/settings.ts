import { getDb, persistDb } from "./index"

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

export async function getSetting<T>(key: string, defaultValue: T): Promise<T> {
  const db = await getDb()
  const rows = stmtToObjects(db, "SELECT value FROM settings WHERE key = ?", [key])
  if (rows.length === 0) return defaultValue
  try {
    return JSON.parse(rows[0].value as string) as T
  } catch {
    return defaultValue
  }
}

export async function setSetting<T>(key: string, value: T): Promise<void> {
  const db = await getDb()
  const json = JSON.stringify(value)
  const existing = stmtToObjects(db, "SELECT key FROM settings WHERE key = ?", [key])
  if (existing.length > 0) {
    db.run("UPDATE settings SET value = ?, updated_at = datetime('now') WHERE key = ?", [json, key])
  } else {
    db.run("INSERT INTO settings (key, value) VALUES (?, ?)", [key, json])
  }
  persistDb()
}

export async function getAllSettings(): Promise<Record<string, unknown>> {
  const db = await getDb()
  const rows = stmtToObjects(db, "SELECT key, value FROM settings")
  const result: Record<string, unknown> = {}
  for (const row of rows) {
    try {
      result[row.key as string] = JSON.parse(row.value as string)
    } catch {
      result[row.key as string] = row.value
    }
  }
  return result
}
