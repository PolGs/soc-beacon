import { cookies } from "next/headers"
import { redirect } from "next/navigation"

const SESSION_COOKIE = "soc-beacon-session"
const DEFAULT_USERNAME = "admin"
const DEFAULT_PASSWORD = "admin"

export async function login(username: string, password: string): Promise<boolean> {
  if (username === DEFAULT_USERNAME && password === DEFAULT_PASSWORD) {
    const cookieStore = await cookies()
    cookieStore.set(SESSION_COOKIE, btoa(JSON.stringify({ user: username, ts: Date.now() })), {
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
