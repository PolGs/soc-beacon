import { LogExplorer } from "@/components/log-explorer"

export default function LogsPage() {
  return (
    <div className="p-6 flex flex-col gap-6">
      <div>
        <h1 className="text-lg font-semibold text-foreground">Log Explorer</h1>
        <p className="text-xs text-muted-foreground mt-0.5">
          Real-time log stream with filtering and search capabilities
        </p>
      </div>
      <LogExplorer />
    </div>
  )
}
