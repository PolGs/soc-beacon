export async function onRequestError() {
  // no-op, required for instrumentation file
}

export async function register() {
  // Only run on the Node.js server runtime, not Edge
  if (typeof window !== "undefined") return
  if (process.env.NEXT_RUNTIME === "edge") return

  try {
    const { startSyslogIfEnabled } = await import("@/lib/ingestion/syslog-manager")
    await startSyslogIfEnabled()
  } catch (err) {
    console.error("[instrumentation] Failed to start syslog:", err)
  }

  try {
    const { getSetting } = await import("@/lib/db/settings")
    const { runRetentionCleanup } = await import("@/lib/db/retention")
    const runCleanup = async () => {
      const general = await getSetting<{ retentionDays?: number }>("general", { retentionDays: 90 })
      const retentionDays = typeof general.retentionDays === "number" ? general.retentionDays : 90
      await runRetentionCleanup(retentionDays)
    }
    await runCleanup()
    setInterval(() => {
      runCleanup().catch((err) => {
        console.error("[retention] Cleanup failed:", err)
      })
    }, 24 * 60 * 60 * 1000)
  } catch (err) {
    console.error("[retention] Failed to schedule cleanup:", err)
  }
}
