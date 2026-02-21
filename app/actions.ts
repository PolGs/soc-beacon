"use server"

import { login, logout, getSession } from "@/lib/auth"
import { redirect } from "next/navigation"
import { revalidatePath } from "next/cache"
import { setSetting } from "@/lib/db/settings"
import { changePassword } from "@/lib/db/users"
import { deleteAlert as dbDeleteAlert, updateAlertIncidentStatus as dbUpdateAlertIncidentStatus, updateAlertVerdict as dbUpdateAlertVerdict } from "@/lib/db/alerts"
import { addThreatFeed, removeThreatFeed, toggleThreatFeed, updateThreatFeedApiKey } from "@/lib/db/threat-feeds"
import { toggleYaraRule } from "@/lib/db/yara-rules"
import type { IncidentStatus, AlertVerdict } from "@/lib/types"

// Auth actions

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

export async function changePasswordAction(
  currentPassword: string,
  newPassword: string
): Promise<{ success: boolean; error?: string }> {
  const session = await getSession()
  if (!session) return { success: false, error: "Not authenticated" }

  if (newPassword.length < 8) {
    return { success: false, error: "Password must be at least 8 characters" }
  }

  return changePassword(session.user, currentPassword, newPassword)
}

// Settings actions

export async function saveSettingsAction(
  section: string,
  data: string
): Promise<{ success: boolean; error?: string }> {
  try {
    const parsed = JSON.parse(data) as Record<string, unknown>

    if (section === "llm") {
      const apiKey = String(parsed.apiKey || "").trim()
      if (/\s/.test(apiKey)) {
        return { success: false, error: "LLM API key looks invalid (contains spaces/newlines). Paste only the key value." }
      }
      parsed.provider = "openai"
      parsed.apiKey = apiKey
    }

    await setSetting(section, parsed)
    revalidatePath("/dashboard/settings")
    revalidatePath("/dashboard")
    return { success: true }
  } catch (e) {
    return { success: false, error: String(e) }
  }
}

// Alert actions

export async function updateAlertIncidentStatusAction(
  alertId: string,
  incidentStatus: IncidentStatus
): Promise<{ success: boolean }> {
  await dbUpdateAlertIncidentStatus(alertId, incidentStatus)
  revalidatePath("/dashboard/alerts")
  revalidatePath(`/dashboard/alerts/${alertId}`)
  revalidatePath("/dashboard")
  return { success: true }
}

export async function updateAlertVerdictAction(
  alertId: string,
  verdict: AlertVerdict
): Promise<{ success: boolean }> {
  await dbUpdateAlertVerdict(alertId, verdict)
  revalidatePath("/dashboard/alerts")
  revalidatePath(`/dashboard/alerts/${alertId}`)
  revalidatePath("/dashboard")
  return { success: true }
}

export async function deleteAlertAction(alertId: string): Promise<{ success: boolean; error?: string }> {
  try {
    await dbDeleteAlert(alertId)
    revalidatePath("/dashboard/alerts")
    revalidatePath("/dashboard")
    return { success: true }
  } catch (e) {
    return { success: false, error: String(e) }
  }
}

// Threat feed actions

export async function addThreatFeedAction(data: {
  name: string
  url: string
  apiKey?: string
}): Promise<{ success: boolean; id?: string }> {
  const id = await addThreatFeed(data)
  revalidatePath("/dashboard/settings")
  return { success: true, id }
}

export async function removeThreatFeedAction(id: string): Promise<{ success: boolean }> {
  await removeThreatFeed(id)
  revalidatePath("/dashboard/settings")
  return { success: true }
}

export async function toggleThreatFeedAction(
  id: string,
  enabled: boolean
): Promise<{ success: boolean }> {
  await toggleThreatFeed(id, enabled)
  revalidatePath("/dashboard/settings")
  return { success: true }
}

export async function updateThreatFeedApiKeyAction(
  id: string,
  apiKey: string
): Promise<{ success: boolean }> {
  await updateThreatFeedApiKey(id, apiKey)
  revalidatePath("/dashboard/settings")
  return { success: true }
}

// YARA rule actions

export async function toggleYaraRuleAction(
  id: string,
  enabled: boolean
): Promise<{ success: boolean }> {
  await toggleYaraRule(id, enabled)
  revalidatePath("/dashboard/settings")
  return { success: true }
}

// Enrichment action (trigger LLM enrichment)
export async function triggerEnrichmentAction(
  alertId: string
): Promise<{ success: boolean; error?: string }> {
  try {
    const { enrichAlertWithLLM } = await import("@/lib/llm/enrich")
    await enrichAlertWithLLM(alertId)
    revalidatePath(`/dashboard/alerts/${alertId}`)
    return { success: true }
  } catch (e) {
    return { success: false, error: String(e) }
  }
}

// Trigger threat intel enrichment
export async function triggerThreatIntelAction(
  alertId: string
): Promise<{ success: boolean; error?: string }> {
  try {
    const { enrichAlertWithThreatIntel } = await import("@/lib/threat-intel/enrich")
    await enrichAlertWithThreatIntel(alertId)
    revalidatePath(`/dashboard/alerts/${alertId}`)
    return { success: true }
  } catch (e) {
    return { success: false, error: String(e) }
  }
}
