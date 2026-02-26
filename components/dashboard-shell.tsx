"use client"

import Link from "next/link"
import Image from "next/image"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import { forceChangeDefaultPasswordAction, logoutAction } from "@/app/actions"
import {
  LayoutDashboard,
  ShieldAlert,
  Settings,
  FileText,
  Lightbulb,
  LogOut,
  ChevronLeft,
  ChevronRight,
  Lock,
  Sun,
  Moon,
} from "lucide-react"
import { useState, useTransition } from "react"
import { useTheme } from "next-themes"
import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { toast } from "sonner"

const navItems = [
  { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { href: "/dashboard/alerts", label: "Alerts", icon: ShieldAlert },
  { href: "/dashboard/recommendations", label: "Recommendations", icon: Lightbulb },
  { href: "/dashboard/system-logs", label: "System Logs", icon: FileText },
  { href: "/dashboard/settings", label: "Settings", icon: Settings },
]

export function DashboardShell({
  children,
  user,
  requirePasswordReset,
}: {
  children: React.ReactNode
  user: string
  requirePasswordReset: boolean
}) {
  const pathname = usePathname()
  const [collapsed, setCollapsed] = useState(false)
  const [newPassword, setNewPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [isPending, startTransition] = useTransition()
  const { resolvedTheme, setTheme } = useTheme()
  const darkMode = resolvedTheme !== "light"

  const handleForcePasswordChange = () => {
    if (newPassword.length < 8) {
      toast.error("Password must be at least 8 characters")
      return
    }
    if (newPassword !== confirmPassword) {
      toast.error("Passwords do not match")
      return
    }
    startTransition(async () => {
      const result = await forceChangeDefaultPasswordAction(newPassword)
      if (result.success) {
        toast.success("Password updated. Please keep it secure.")
        setNewPassword("")
        setConfirmPassword("")
      } else {
        toast.error(result.error || "Failed to update password")
      }
    })
  }

  return (
    <TooltipProvider delayDuration={0}>
      <div className="flex h-screen overflow-hidden">
        <Dialog open={requirePasswordReset} onOpenChange={() => {}}>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Lock className="w-4 h-4" />
                Set a new admin password
              </DialogTitle>
              <DialogDescription>
                The default admin password is still active. Please set a new password before continuing.
              </DialogDescription>
            </DialogHeader>
            <div className="flex flex-col gap-3">
              <div className="flex flex-col gap-1.5">
                <span className="text-[11px] text-muted-foreground">New Password</span>
                <Input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Minimum 8 characters"
                  className="bg-background/60 border-border/50 h-9 text-xs font-mono focus:border-foreground/30"
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <span className="text-[11px] text-muted-foreground">Confirm Password</span>
                <Input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Repeat new password"
                  className="bg-background/60 border-border/50 h-9 text-xs font-mono focus:border-foreground/30"
                />
              </div>
            </div>
            <DialogFooter>
              <Button className="h-9 text-xs" onClick={handleForcePasswordChange} disabled={isPending}>
                {isPending ? "Updating..." : "Update Password"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Sidebar */}
        <aside
          className={cn(
            "flex flex-col border-r border-border/50 bg-card/40 backdrop-blur-xl transition-all duration-300 shrink-0",
            collapsed ? "w-16" : "w-56"
          )}
        >
          {/* Brand */}
          <div className={cn(
            "flex items-center h-14 border-b border-border/50 px-4 shrink-0",
            collapsed ? "justify-center" : "gap-2.5"
          )}>
            <Image src="/logo.png" alt="SOC Beacon" width={28} height={28} className="shrink-0 rounded" />
            {!collapsed && (
              <span className="text-sm font-semibold tracking-tight text-foreground truncate">
                SOC Beacon
              </span>
            )}
          </div>

          {/* Nav */}
          <nav className="flex-1 py-3 px-2 flex flex-col gap-0.5 overflow-y-auto">
            {navItems.map((item) => {
              const isActive =
                item.href === "/dashboard"
                  ? pathname === "/dashboard"
                  : pathname.startsWith(item.href)

              const linkContent = (
                <Link
                  key={item.href}
                  href={item.href}
                  className={cn(
                    "flex items-center gap-3 rounded-md text-sm transition-colors h-9",
                    collapsed ? "justify-center px-0" : "px-3",
                    isActive
                      ? "bg-foreground/10 text-foreground"
                      : "text-muted-foreground hover:text-foreground hover:bg-foreground/5"
                  )}
                >
                  <item.icon className="w-4 h-4 shrink-0" />
                  {!collapsed && <span className="truncate">{item.label}</span>}
                </Link>
              )

              if (collapsed) {
                return (
                  <Tooltip key={item.href}>
                    <TooltipTrigger asChild>{linkContent}</TooltipTrigger>
                    <TooltipContent side="right" className="bg-card border-border text-foreground">
                      {item.label}
                    </TooltipContent>
                  </Tooltip>
                )
              }

              return linkContent
            })}
          </nav>

          {/* Footer */}
          <div className="border-t border-border/50 p-2 shrink-0 flex flex-col gap-1">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setCollapsed(!collapsed)}
              className={cn(
                "h-8 text-muted-foreground hover:text-foreground",
                collapsed ? "w-full justify-center px-0" : "w-full justify-start px-3"
              )}
            >
              {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
              {!collapsed && <span className="ml-2 text-xs">Collapse</span>}
            </Button>

            <Button
              variant="ghost"
              size="sm"
              onClick={() => setTheme(darkMode ? "light" : "dark")}
              className={cn(
                "h-8 text-muted-foreground hover:text-foreground w-full",
                collapsed ? "justify-center px-0" : "justify-start px-3"
              )}
            >
              {darkMode ? <Sun className="w-4 h-4 shrink-0" /> : <Moon className="w-4 h-4 shrink-0" />}
              {!collapsed && <span className="ml-2 text-xs">{darkMode ? "Light Theme" : "Dark Theme"}</span>}
            </Button>

            <form action={logoutAction}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    type="submit"
                    variant="ghost"
                    size="sm"
                    className={cn(
                      "h-8 text-muted-foreground hover:text-foreground w-full",
                      collapsed ? "justify-center px-0" : "justify-start px-3"
                    )}
                  >
                    <LogOut className="w-4 h-4 shrink-0" />
                    {!collapsed && <span className="ml-2 text-xs truncate">{user}</span>}
                  </Button>
                </TooltipTrigger>
                {collapsed && (
                  <TooltipContent side="right" className="bg-card border-border text-foreground">
                    Logout ({user})
                  </TooltipContent>
                )}
              </Tooltip>
            </form>
          </div>
        </aside>

        {/* Main content */}
        <main className="flex-1 overflow-y-auto bg-background">
          {children}
        </main>
      </div>
    </TooltipProvider>
  )
}
