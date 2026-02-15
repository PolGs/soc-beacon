import { getSession } from "@/lib/auth"
import { redirect } from "next/navigation"
import { LoginForm } from "@/components/login-form"

export default async function LoginPage() {
  const session = await getSession()
  if (session) {
    redirect("/dashboard")
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background relative overflow-hidden">
      {/* Subtle grid background */}
      <div
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage:
            "linear-gradient(hsl(0 0% 50%) 1px, transparent 1px), linear-gradient(90deg, hsl(0 0% 50%) 1px, transparent 1px)",
          backgroundSize: "60px 60px",
        }}
      />

      {/* Radial glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full bg-foreground/[0.02] blur-3xl" />

      <div className="relative z-10 w-full max-w-sm px-6">
        <div className="glass-strong rounded-lg p-8">
          {/* Logo / Brand */}
          <div className="flex flex-col items-center gap-3 mb-8">
            <div className="flex items-center gap-2">
              <svg
                viewBox="0 0 24 24"
                fill="none"
                className="w-8 h-8"
                stroke="currentColor"
                strokeWidth="1.5"
              >
                <path
                  d="M12 2L3 7v10l9 5 9-5V7l-9-5z"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
                <circle cx="12" cy="12" r="3" />
                <path d="M12 2v7M12 15v7M3 7l6.5 3.5M14.5 13.5L21 17M21 7l-6.5 3.5M9.5 13.5L3 17" strokeLinecap="round" />
              </svg>
              <h1 className="text-xl font-semibold tracking-tight text-foreground">
                SOC Beacon
              </h1>
            </div>
            <p className="text-xs text-muted-foreground tracking-wide uppercase">
              Security Operations Platform
            </p>
          </div>

          <LoginForm />

          <div className="mt-6 pt-4 border-t border-border/50">
            <p className="text-[11px] text-muted-foreground/60 text-center leading-relaxed">
              Default credentials: admin / admin
            </p>
          </div>
        </div>

        <p className="text-[11px] text-muted-foreground/40 text-center mt-6">
          SOC Beacon v1.0.0 &middot; Open Source
        </p>
      </div>
    </div>
  )
}
