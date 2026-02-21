import { getAlertById } from "@/lib/db/alerts"
import { notFound } from "next/navigation"
import { AlertDetail } from "@/components/alert-detail"
import Link from "next/link"
import { ChevronLeft } from "lucide-react"

export const dynamic = "force-dynamic"

export default async function AlertDetailPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params
  const alert = await getAlertById(id)
  if (!alert) notFound()

  return (
    <div className="p-6 flex flex-col gap-6">
      <div className="flex items-center gap-3">
        <Link
          href="/dashboard/alerts"
          className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          <ChevronLeft className="w-3.5 h-3.5" />
          Back to Alerts
        </Link>
      </div>
      <AlertDetail alert={alert} />
    </div>
  )
}
