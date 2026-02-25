import { requireAuth } from "@/lib/auth"
import { DashboardShell } from "@/components/dashboard-shell"
import { isDefaultAdminPassword } from "@/lib/db/users"

export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const session = await requireAuth()
  const needsPasswordReset = session.user === "admin" ? await isDefaultAdminPassword() : false

  return <DashboardShell user={session.user} requirePasswordReset={needsPasswordReset}>{children}</DashboardShell>
}
