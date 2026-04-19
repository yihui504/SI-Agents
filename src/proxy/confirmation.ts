import type { ChatCompletionMessage, ChatCompletionResponse } from "./types.ts"

const POLICY_CONFIRMATION_SUFFIX = "\n\n如果你确认要继续，请回复 **Yes**；否则回复 **No**。"

export function isPolicyConfirmationReply(messages: ChatCompletionMessage[]): boolean {
  if (messages.length < 2) return false
  const lastUserMessage = [...messages].reverse().find((m) => m.role === "user")
  if (!lastUserMessage || lastUserMessage.content === null) return false
  const content = typeof lastUserMessage.content === "string"
    ? lastUserMessage.content
    : lastUserMessage.content.map((p) => p.text ?? "").join("")
  return content.trim().toLowerCase() === "yes" || content.trim().toLowerCase() === "no"
}

export function extractConfirmationReply(messages: ChatCompletionMessage[]): "yes" | "no" | null {
  const lastUserMessage = [...messages].reverse().find((m) => m.role === "user")
  if (!lastUserMessage || lastUserMessage.content === null) return null
  const content = typeof lastUserMessage.content === "string"
    ? lastUserMessage.content
    : lastUserMessage.content.map((p) => p.text ?? "").join("")
  const trimmed = content.trim().toLowerCase()
  if (trimmed === "yes") return "yes"
  if (trimmed === "no") return "no"
  return null
}

export function createConfirmationPrompt(blockedMessage: string): string {
  return blockedMessage + POLICY_CONFIRMATION_SUFFIX
}

export function createMockResponse(message: string, model: string = "si-agents-proxy"): ChatCompletionResponse {
  return {
    id: `chatcmpl-${crypto.randomUUID()}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [
      {
        index: 0,
        message: {
          role: "assistant",
          content: message,
        },
        finish_reason: "stop",
      },
    ],
    usage: {
      prompt_tokens: 0,
      completion_tokens: 0,
      total_tokens: 0,
    },
  }
}

export function hasPolicyConfirmationInHistory(messages: ChatCompletionMessage[]): boolean {
  for (const msg of messages) {
    if (msg.role === "assistant" && msg.content !== null) {
      const content = typeof msg.content === "string"
        ? msg.content
        : msg.content.map((p) => p.text ?? "").join("")
      if (content.includes(POLICY_CONFIRMATION_SUFFIX.trim())) {
        return true
      }
    }
  }
  return false
}
