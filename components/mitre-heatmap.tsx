interface MitreHeatmapProps {
  data: Array<{ technique: string; count: number }>
}

export function MitreHeatmap({ data }: MitreHeatmapProps) {
  const max = data.length > 0 ? Math.max(...data.map((t) => t.count)) : 1

  return (
    <div className="glass rounded-lg p-4">
      <div className="mb-3">
        <h3 className="text-sm font-medium text-foreground">MITRE ATT&CK</h3>
        <p className="text-[11px] text-muted-foreground mt-0.5">Top techniques detected</p>
      </div>
      <div className="flex flex-col gap-1.5">
        {data.slice(0, 6).map((item) => {
          const intensity = item.count / max
          // Interpolate from blue (low) through amber to red (high)
          const hue = 25 - intensity * 25 // 25 (orange) → 0 (red)
          const sat = 60 + intensity * 30
          const light = 50 + intensity * 10
          return (
            <div
              key={item.technique}
              className="flex items-center gap-2 px-2 py-1.5 rounded"
              style={{
                backgroundColor: `hsla(${hue}, ${sat}%, ${light}%, ${intensity * 0.12})`,
              }}
            >
              <span
                className="text-[11px] font-mono tabular-nums shrink-0 font-medium"
                style={{ color: `hsl(${hue} ${sat}% ${light}%)` }}
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
