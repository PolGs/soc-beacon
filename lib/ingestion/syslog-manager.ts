import { SyslogListener } from "./syslog-listener"
import { getSetting } from "@/lib/db/settings"

let listener: SyslogListener | null = null

export async function startSyslogIfEnabled(): Promise<void> {
  const syslogSettings = await getSetting<{
    enabled: boolean
    port: number
    protocol: "udp" | "tcp" | "both"
  }>("syslog", { enabled: true, port: 1514, protocol: "both" })

  if (!syslogSettings.enabled) {
    console.log("[syslog] Syslog receiver is disabled in settings")
    return
  }

  try {
    listener = new SyslogListener({
      port: syslogSettings.port,
      protocol: syslogSettings.protocol,
    })
    await listener.start()
  } catch (err) {
    console.error("[syslog] Failed to start listener:", err)
    listener = null
  }
}

export async function restartSyslog(): Promise<void> {
  if (listener) {
    await listener.stop()
    listener = null
  }
  await startSyslogIfEnabled()
}

export async function stopSyslog(): Promise<void> {
  if (listener) {
    await listener.stop()
    listener = null
  }
}

export function isSyslogRunning(): boolean {
  return listener?.isRunning() ?? false
}
