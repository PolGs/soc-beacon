import Anthropic from "@anthropic-ai/sdk"
import type { LLMClient, LLMMessage, LLMResponse } from "./index"

interface AnthropicOptions {
  apiKey: string
  model: string
  maxTokens: number
  temperature: number
}

export function createAnthropicClient(options: AnthropicOptions): LLMClient {
  const client = new Anthropic({
    apiKey: options.apiKey,
  })

  return {
    async chat(messages: LLMMessage[]): Promise<LLMResponse> {
      // Separate system message from user/assistant messages
      const systemMsg = messages.find((m) => m.role === "system")
      const chatMessages = messages
        .filter((m) => m.role !== "system")
        .map((m) => ({
          role: m.role as "user" | "assistant",
          content: m.content,
        }))

      const response = await client.messages.create({
        model: options.model,
        max_tokens: options.maxTokens,
        temperature: options.temperature,
        ...(systemMsg ? { system: systemMsg.content } : {}),
        messages: chatMessages,
      })

      const content = response.content
        .filter((block) => block.type === "text")
        .map((block) => {
          if (block.type === "text") return block.text
          return ""
        })
        .join("")

      return { content }
    },
  }
}
