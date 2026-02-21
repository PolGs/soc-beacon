import { getSetting } from "@/lib/db/settings"
import type { LLMProvider } from "@/lib/types"

export interface LLMMessage {
  role: "system" | "user" | "assistant"
  content: string
}

export interface LLMResponse {
  content: string
}

export interface LLMClient {
  chat(messages: LLMMessage[]): Promise<LLMResponse>
}

export async function getLLMClient(): Promise<LLMClient> {
  const settings = await getSetting<{
    provider: LLMProvider
    apiKey: string
    model: string
    endpoint: string
    maxTokens: number
    temperature: number
    analysisAgents?: number
    autoStatusConfidenceThreshold?: number
  }>("llm", {
    provider: "openai",
    apiKey: "",
    model: "gpt-4.1-nano",
    endpoint: "",
    maxTokens: 700,
    temperature: 0.3,
    analysisAgents: 3,
    autoStatusConfidenceThreshold: 90,
  })

  const apiKey = (settings.apiKey || "").trim()
  if (!apiKey) {
    throw new Error("LLM API key not configured")
  }

  // OpenAI-only mode: keep endpoint safe/default.
  const endpoint =
    settings.endpoint && /api\.openai\.com/i.test(settings.endpoint)
      ? settings.endpoint
      : undefined

  const { createOpenAIClient } = await import("./openai-provider")
  return createOpenAIClient({
    apiKey,
    model: settings.model || "gpt-4.1-nano",
    endpoint,
    maxTokens: settings.maxTokens,
    temperature: settings.temperature,
  })
}
