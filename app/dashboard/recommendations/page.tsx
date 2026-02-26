import { generateSiemRecommendations } from "@/lib/recommendations/siem-recommendations"
import { Lightbulb, Sparkles } from "lucide-react"

export const dynamic = "force-dynamic"

export default async function RecommendationsPage() {
  const recs = await generateSiemRecommendations()

  return (
    <div className="p-6 flex flex-col gap-6">
      <div>
        <h1 className="text-lg font-semibold text-foreground">Recommendations</h1>
        <p className="text-xs text-muted-foreground mt-0.5">
          AI-powered tuning guidance to reduce noisy alerts and keep only high-confidence tickets.
        </p>
      </div>

      <div className="glass rounded-lg p-5 flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-foreground/60" />
            <span className="text-sm text-foreground font-medium">SOC Tuning Plan</span>
          </div>
          <span className="text-[11px] text-muted-foreground">
            Mode: {recs.mode === "ai" ? "AI" : "Heuristic"} · {new Date(recs.generatedAt).toLocaleString()}
          </span>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          <div className="bg-background/50 rounded-md border border-border/30 px-3 py-2">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Labeled</p>
            <p className="text-sm text-foreground font-semibold">{recs.context.labeledAlerts}</p>
          </div>
          <div className="bg-background/50 rounded-md border border-border/30 px-3 py-2">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Malicious</p>
            <p className="text-sm text-foreground font-semibold">{recs.context.malicious}</p>
          </div>
          <div className="bg-background/50 rounded-md border border-border/30 px-3 py-2">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide">False Positive</p>
            <p className="text-sm text-foreground font-semibold">{recs.context.falsePositive}</p>
          </div>
          <div className="bg-background/50 rounded-md border border-border/30 px-3 py-2">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Open Critical</p>
            <p className="text-sm text-foreground font-semibold">{recs.context.criticalOpen}</p>
          </div>
        </div>

        <div className="bg-background/50 rounded-md border border-border/30 p-4">
          <div className="flex items-center gap-2 mb-3">
            <Lightbulb className="w-3.5 h-3.5 text-foreground/60" />
            <span className="text-[11px] text-muted-foreground uppercase tracking-wide">Recommended Actions</span>
          </div>
          <ul className="space-y-2">
            {recs.bullets.map((bullet, index) => (
              <li key={`${index}-${bullet.slice(0, 16)}`} className="text-xs text-foreground/85 leading-relaxed flex gap-2">
                <span className="text-muted-foreground/60 font-mono">{index + 1}.</span>
                <span>{bullet}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )
}

