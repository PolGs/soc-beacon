import OpenAI from "openai"
import type { LLMClient, LLMMessage, LLMResponse } from "./index"

interface OpenAIOptions {
  apiKey: string
  model: string
  endpoint?: string
  maxTokens: number
  temperature: number
}

export function createOpenAIClient(options: OpenAIOptions): LLMClient {
  const client = new OpenAI({
    apiKey: options.apiKey,
    ...(options.endpoint ? { baseURL: options.endpoint } : {}),
  })

  return {
    async chat(messages: LLMMessage[]): Promise<LLMResponse> {
      const response = await client.chat.completions.create({
        model: options.model,
        messages: messages.map((m) => ({ role: m.role, content: m.content })),
        max_tokens: options.maxTokens,
        temperature: options.temperature,
        response_format: { type: "json_object" },
      })

      const content = response.choices[0]?.message?.content || ""
      return { content }
    },
  }
}
