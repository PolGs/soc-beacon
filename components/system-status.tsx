interface SystemStatusProps {
  settings: Record<string, unknown>
}

export function SystemStatus({ settings }: SystemStatusProps) {
  const syslog = (settings.syslog || {}) as Record<string, unknown>
  const api = (settings.api || {}) as Record<string, unknown>
  const yaraSettings = (settings.yara || {}) as Record<string, unknown>
  const llmSettings = (settings.llm || {}) as Record<string, unknown>
  const syslogOut = (settings.syslogOutput || {}) as Record<string, unknown>

  const services = [
    {
      name: "Syslog Receiver",
      enabled: syslog.enabled !== false,
      port: syslog.enabled !== false ? `${((syslog.protocol as string) || "both").toUpperCase()}/${syslog.port || 1514}` : null,
    },
    {
      name: "API Ingestion",
      enabled: api.enabled !== false,
      port: api.enabled !== false ? `TCP/${api.port || 8443}` : null,
    },
    {
      name: "YARA Engine",
      enabled: yaraSettings.enabled !== false,
      port: null,
    },
    {
      name: "LLM Enrichment",
      enabled: !!(llmSettings.apiKey),
      port: null,
    },
    {
      name: "Syslog Output",
      enabled: !!(syslogOut.enabled),
      port: syslogOut.enabled ? `TCP/${syslogOut.port || 5514}` : null,
    },
  ]

  return (
    <div className="glass rounded-lg p-4">
      <div className="mb-3">
        <h3 className="text-sm font-medium text-foreground">System Status</h3>
        <p className="text-[11px] text-muted-foreground mt-0.5">Service health</p>
      </div>
      <div className="flex flex-col gap-2">
        {services.map((svc) => (
          <div key={svc.name} className="flex items-center justify-between py-1">
            <div className="flex items-center gap-2">
              <span className={`w-1.5 h-1.5 rounded-full ${svc.enabled ? "bg-[hsl(142,71%,45%)]" : "bg-muted-foreground/30"}`} />
              <span className={`text-xs ${svc.enabled ? "text-foreground/80" : "text-muted-foreground/50"}`}>{svc.name}</span>
            </div>
            {svc.port && (
              <span className="text-[10px] font-mono text-muted-foreground">{svc.port}</span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
