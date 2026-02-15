"use server"

import { login, logout } from "@/lib/auth"
import { redirect } from "next/navigation"

export async function loginAction(_prevState: { error: string } | null, formData: FormData) {
  const username = formData.get("username") as string
  const password = formData.get("password") as string

  if (!username || !password) {
    return { error: "Username and password are required" }
  }

  const success = await login(username, password)

  if (!success) {
    return { error: "Invalid credentials" }
  }

  redirect("/dashboard")
}

export async function logoutAction() {
  await logout()
  redirect("/login")
}
