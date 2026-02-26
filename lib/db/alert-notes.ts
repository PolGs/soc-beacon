import { nanoid } from "nanoid"
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

export interface AlertNote {
  id: string
  alertId: string
  username: string
  noteText: string
  imageData?: string | null
  imageMime?: string | null
  createdAt: string
}

export async function getAlertNotes(alertId: string): Promise<AlertNote[]> {
  const db = await getDb()
  const rows = stmtToObjects(
    db,
    "SELECT id, alert_id, username, note_text, image_data, image_mime, created_at FROM alert_notes WHERE alert_id = ? ORDER BY created_at DESC",
    [alertId]
  )
  return rows.map((r) => ({
    id: r.id as string,
    alertId: r.alert_id as string,
    username: r.username as string,
    noteText: r.note_text as string,
    imageData: (r.image_data as string) || null,
    imageMime: (r.image_mime as string) || null,
    createdAt: (r.created_at as string) || "",
  }))
}

export async function createAlertNote(data: {
  alertId: string
  username: string
  noteText: string
  imageData?: string | null
  imageMime?: string | null
}): Promise<string> {
  const db = await getDb()
  const id = `NTE-${nanoid(10).toUpperCase()}`
  db.run(
    "INSERT INTO alert_notes (id, alert_id, username, note_text, image_data, image_mime) VALUES (?, ?, ?, ?, ?, ?)",
    [id, data.alertId, data.username, data.noteText, data.imageData || null, data.imageMime || null]
  )
  persistDb()
  return id
}
