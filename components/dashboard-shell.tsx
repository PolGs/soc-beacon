"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import { logoutAction } from "@/app/actions"
import {
  LayoutDashboard,
  ShieldAlert,
  ScrollText,
  Settings,
  LogOut,
  Radio,
  ChevronLeft,
  ChevronRight,
} from "lucide-react"
import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"

const navItems = [
  { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { href: "/dashboard/alerts", label: "Alerts", icon: ShieldAlert },
  { href: "/dashboard/logs", label: "Log Explorer", icon: ScrollText },
  { href: "/dashboard/settings", label: "Settings", icon: Settings },
]

export function DashboardShell({
  children,
  user,
}: {
  children: React.ReactNode
  user: string
}) {
  const pathname = usePathname()
  const [collapsed, setCollapsed] = useState(false)

  return (
    <TooltipProvider delayDuration={0}>
      <div className="flex h-screen overflow-hidden">
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
            <Radio className="w-5 h-5 text-foreground shrink-0" />
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
