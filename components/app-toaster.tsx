"use client"

import { Toaster } from "sonner"
import { useTheme } from "next-themes"

export function AppToaster() {
  const { resolvedTheme } = useTheme()
  const dark = resolvedTheme !== "light"

  return (
    <Toaster
      theme={dark ? "dark" : "light"}
      toastOptions={
        dark
          ? {
              style: {
                background: "hsl(0 0% 7%)",
                border: "1px solid hsl(0 0% 15%)",
                color: "hsl(0 0% 95%)",
              },
            }
          : undefined
      }
    />
  )
}
