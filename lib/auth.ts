import { cookies } from "next/headers"
import { redirect } from "next/navigation"
import { authenticateUser } from "@/lib/db/users"

const SESSION_COOKIE = "soc-beacon-session"

export async function login(username: string, password: string): Promise<boolean> {
  const user = await authenticateUser(username, password)
  if (user) {
    const cookieStore = await cookies()
    cookieStore.set(SESSION_COOKIE, btoa(JSON.stringify({ user: user.username, ts: Date.now() })), {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 60 * 60 * 24 * 7, // 7 days
      path: "/",
    })
    return true
  }
  return false
}

export async function logout() {
  const cookieStore = await cookies()
  cookieStore.delete(SESSION_COOKIE)
}

export async function getSession(): Promise<{ user: string } | null> {
  const cookieStore = await cookies()
  const session = cookieStore.get(SESSION_COOKIE)
  if (!session?.value) return null
  try {
    return JSON.parse(atob(session.value))
  } catch {
    return null
  }
}

export async function requireAuth() {
  const session = await getSession()
  if (!session) {
    redirect("/login")
  }
  return session
}
