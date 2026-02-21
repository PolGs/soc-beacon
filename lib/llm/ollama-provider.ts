import OpenAI from "openai"
import type { LLMClient, LLMMessage, LLMResponse } from "./index"

interface OllamaOptions {
  model: string
  endpoint: string
  maxTokens: number
  temperature: number
}

export function createOllamaClient(options: OllamaOptions): LLMClient {
  // Ollama provides an OpenAI-compatible API
  const client = new OpenAI({
    apiKey: "ollama", // Ollama doesn't need a real key
    baseURL: `${options.endpoint}/v1`,
  })

  return {
    async chat(messages: LLMMessage[]): Promise<LLMResponse> {
      const response = await client.chat.completions.create({
        model: options.model,
        messages: messages.map((m) => ({ role: m.role, content: m.content })),
        max_tokens: options.maxTokens,
        temperature: options.temperature,
      })

      const content = response.choices[0]?.message?.content || ""
      return { content }
    },
  }
}
