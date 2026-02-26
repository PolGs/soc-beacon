interface DetectionQualityProps {
  report: {
    labeledCount: number
    truePositiveCount: number
    falsePositiveCount: number
    detectors: Array<{ detector: string; tp: number; fp: number; precision: number; recall: number }>
    bySource: Array<{ source: string; tp: number; fp: number; precision: number; recall: number }>
  }
}

export function DetectionQuality({ report }: DetectionQualityProps) {
  return (
    <div className="glass rounded-lg p-4 flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-medium text-foreground">Detection Quality</h3>
          <p className="text-[11px] text-muted-foreground">
            Labeled set: {report.labeledCount} ({report.truePositiveCount} TP / {report.falsePositiveCount} FP)
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-background/40 rounded-md border border-border/20 p-3">
          <p className="text-[11px] text-muted-foreground mb-2">Precision / Recall by Detector</p>
          <div className="space-y-2">
            {report.detectors.map((d) => (
              <div key={d.detector} className="text-[11px] flex items-center justify-between">
                <span className="font-mono text-foreground/75">{d.detector}</span>
                <span className="text-muted-foreground">
                  P {d.precision}% · R {d.recall}% · TP {d.tp} / FP {d.fp}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-background/40 rounded-md border border-border/20 p-3">
          <p className="text-[11px] text-muted-foreground mb-2">Precision / Recall by Source</p>
          <div className="space-y-2">
            {report.bySource.map((s) => (
              <div key={s.source} className="text-[11px] flex items-center justify-between">
                <span className="font-mono text-foreground/75 truncate max-w-[180px]" title={s.source}>
                  {s.source}
                </span>
                <span className="text-muted-foreground">
                  P {s.precision}% · R {s.recall}% · TP {s.tp} / FP {s.fp}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

