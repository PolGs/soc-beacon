import { NextResponse } from "next/server"
import { getAlertCounts } from "@/lib/db/alerts"
import { getLogCount } from "@/lib/db/logs"

export async function GET() {
  try {
    const [alertCounts, logCount] = await Promise.all([getAlertCounts(), getLogCount()])

    return NextResponse.json({
      status: "healthy",
      timestamp: new Date().toISOString(),
      stats: {
        totalAlerts: alertCounts.total,
        totalLogs: logCount,
        alertsBySeverity: alertCounts.severity,
        alertsByStatus: alertCounts.status,
      },
    })
  } catch (err) {
    return NextResponse.json(
      { status: "unhealthy", error: String(err) },
      { status: 500 }
    )
  }
}
