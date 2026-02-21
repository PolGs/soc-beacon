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
}
