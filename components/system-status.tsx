const services = [
  { name: "Syslog Receiver", status: "operational", port: "UDP/514" },
  { name: "API Ingestion", status: "operational", port: "TCP/8443" },
  { name: "YARA Engine", status: "operational", port: null },
  { name: "LLM Enrichment", status: "operational", port: null },
  { name: "Syslog Output", status: "operational", port: "TCP/5514" },
]

export function SystemStatus() {
  return (
    <div className="glass rounded-lg p-4">
      <div className="mb-3">
        <h3 className="text-sm font-medium text-foreground">System Status</h3>
        <p className="text-[11px] text-muted-foreground mt-0.5">Service health</p>
      </div>
      <div className="flex flex-col gap-2">
        {services.map((svc) => (
          <div
            key={svc.name}
            className="flex items-center justify-between py-1"
          >
            <div className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-foreground/70" />
              <span className="text-xs text-foreground/80">{svc.name}</span>
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
