"use client"

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
} from "recharts"

interface AlertTimelineProps {
  data: Array<{ time: string; critical: number; high: number; medium: number; low: number }>
}

const COLORS = {
  critical: "hsl(0 72% 51%)",
  high: "hsl(25 95% 53%)",
  medium: "hsl(45 93% 47%)",
  low: "hsl(217 91% 60%)",
}

export function AlertTimeline({ data }: AlertTimelineProps) {
  return (
    <div className="glass rounded-lg p-4">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-medium text-foreground">Alert Timeline</h3>
          <p className="text-[11px] text-muted-foreground mt-0.5">24-hour distribution by severity</p>
        </div>
        <div className="flex items-center gap-4">
          {[
            { label: "Critical", color: COLORS.critical },
            { label: "High", color: COLORS.high },
            { label: "Medium", color: COLORS.medium },
            { label: "Low", color: COLORS.low },
          ].map((item) => (
            <div key={item.label} className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
              <span className="text-[11px] text-muted-foreground">{item.label}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="h-[220px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.critical} stopOpacity={0.3} />
                <stop offset="95%" stopColor={COLORS.critical} stopOpacity={0} />
              </linearGradient>
              <linearGradient id="highGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.high} stopOpacity={0.25} />
                <stop offset="95%" stopColor={COLORS.high} stopOpacity={0} />
              </linearGradient>
              <linearGradient id="medGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.medium} stopOpacity={0.2} />
                <stop offset="95%" stopColor={COLORS.medium} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(0 0% 15%)" />
            <XAxis dataKey="time" tick={{ fill: "hsl(0 0% 45%)", fontSize: 11 }} axisLine={{ stroke: "hsl(0 0% 15%)" }} tickLine={false} />
            <YAxis tick={{ fill: "hsl(0 0% 45%)", fontSize: 11 }} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={{ backgroundColor: "hsl(0 0% 7%)", border: "1px solid hsl(0 0% 15%)", borderRadius: "6px", fontSize: "12px", color: "hsl(0 0% 90%)" }} />
            <Area type="monotone" dataKey="critical" stroke={COLORS.critical} fill="url(#critGrad)" strokeWidth={1.5} />
            <Area type="monotone" dataKey="high" stroke={COLORS.high} fill="url(#highGrad)" strokeWidth={1.5} />
            <Area type="monotone" dataKey="medium" stroke={COLORS.medium} fill="url(#medGrad)" strokeWidth={1.5} />
            <Area type="monotone" dataKey="low" stroke={COLORS.low} fill="transparent" strokeWidth={1} strokeDasharray="4 4" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
