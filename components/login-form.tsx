"use client"

import { useActionState } from "react"
import { loginAction } from "@/app/actions"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import { Loader2, Lock } from "lucide-react"

export function LoginForm() {
  const [state, formAction, isPending] = useActionState(loginAction, null)

  return (
    <form action={formAction} className="flex flex-col gap-4">
      <div className="flex flex-col gap-2">
        <Label htmlFor="username" className="text-xs text-muted-foreground">
          Username
        </Label>
        <Input
          id="username"
          name="username"
          type="text"
          autoComplete="username"
          required
          placeholder="admin"
          className="bg-background/60 border-border/50 h-9 text-sm placeholder:text-muted-foreground/40 focus:border-foreground/30 focus:ring-foreground/10"
        />
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="password" className="text-xs text-muted-foreground">
          Password
        </Label>
        <Input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;"
          className="bg-background/60 border-border/50 h-9 text-sm placeholder:text-muted-foreground/40 focus:border-foreground/30 focus:ring-foreground/10"
        />
      </div>

      {state?.error && (
        <div className="text-xs text-foreground/80 bg-foreground/5 border border-foreground/10 rounded-md px-3 py-2">
          {state.error}
        </div>
      )}

      <Button
        type="submit"
        disabled={isPending}
        className="w-full h-9 mt-1 bg-foreground text-background hover:bg-foreground/90 text-sm font-medium"
      >
        {isPending ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : (
          <>
            <Lock className="w-3.5 h-3.5 mr-2" />
            Authenticate
          </>
        )}
      </Button>
    </form>
  )
}
