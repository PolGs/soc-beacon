"use client"

import { timelineData } from "@/lib/mock-data"
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
} from "recharts"

export function AlertTimeline() {
  return (
    <div className="glass rounded-lg p-4">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-medium text-foreground">Alert Timeline</h3>
          <p className="text-[11px] text-muted-foreground mt-0.5">24-hour distribution by severity</p>
        </div>
        <div className="flex items-center gap-4">
          {[
            { label: "Critical", color: "hsl(0 0% 90%)" },
            { label: "High", color: "hsl(0 0% 65%)" },
            { label: "Medium", color: "hsl(0 0% 45%)" },
            { label: "Low", color: "hsl(0 0% 30%)" },
          ].map((item) => (
            <div key={item.label} className="flex items-center gap-1.5">
              <span
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: item.color }}
              />
              <span className="text-[11px] text-muted-foreground">{item.label}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="h-[220px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={timelineData} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(0 0% 90%)" stopOpacity={0.3} />
                <stop offset="95%" stopColor="hsl(0 0% 90%)" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="highGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(0 0% 65%)" stopOpacity={0.2} />
                <stop offset="95%" stopColor="hsl(0 0% 65%)" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="medGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(0 0% 45%)" stopOpacity={0.15} />
                <stop offset="95%" stopColor="hsl(0 0% 45%)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(0 0% 15%)" />
            <XAxis
              dataKey="time"
              tick={{ fill: "hsl(0 0% 45%)", fontSize: 11 }}
              axisLine={{ stroke: "hsl(0 0% 15%)" }}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: "hsl(0 0% 45%)", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(0 0% 7%)",
                border: "1px solid hsl(0 0% 15%)",
                borderRadius: "6px",
                fontSize: "12px",
                color: "hsl(0 0% 90%)",
              }}
            />
            <Area
              type="monotone"
              dataKey="critical"
              stroke="hsl(0 0% 90%)"
              fill="url(#critGrad)"
              strokeWidth={1.5}
            />
            <Area
              type="monotone"
              dataKey="high"
              stroke="hsl(0 0% 65%)"
              fill="url(#highGrad)"
              strokeWidth={1.5}
            />
            <Area
              type="monotone"
              dataKey="medium"
              stroke="hsl(0 0% 45%)"
              fill="url(#medGrad)"
              strokeWidth={1.5}
            />
            <Area
              type="monotone"
              dataKey="low"
              stroke="hsl(0 0% 30%)"
              fill="transparent"
              strokeWidth={1}
              strokeDasharray="4 4"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
