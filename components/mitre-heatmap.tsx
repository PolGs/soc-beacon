import { topMitreTechniques } from "@/lib/mock-data"

export function MitreHeatmap() {
  const max = Math.max(...topMitreTechniques.map((t) => t.count))

  return (
    <div className="glass rounded-lg p-4">
      <div className="mb-3">
        <h3 className="text-sm font-medium text-foreground">MITRE ATT&CK</h3>
        <p className="text-[11px] text-muted-foreground mt-0.5">Top techniques detected</p>
      </div>
      <div className="flex flex-col gap-1.5">
        {topMitreTechniques.slice(0, 6).map((item) => {
          const intensity = item.count / max
          return (
            <div
              key={item.technique}
              className="flex items-center gap-2 px-2 py-1.5 rounded"
              style={{
                backgroundColor: `hsla(0, 0%, ${90 - intensity * 60}%, ${intensity * 0.15})`,
              }}
            >
              <span
                className="text-[11px] font-mono tabular-nums shrink-0"
                style={{ color: `hsl(0 0% ${40 + intensity * 50}%)` }}
              >
                {item.count}
              </span>
              <span className="text-[11px] text-foreground/70 truncate">
                {item.technique}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
