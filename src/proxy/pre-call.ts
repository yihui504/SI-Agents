import type { ChatCompletionRequest, ChatCompletionMessage, PreCallResult, ConfirmationEntry } from "./types.ts"
import type { ProxyConfig } from "./types.ts"
import { isPolicyConfirmationReply, extractConfirmationReply, hasPolicyConfirmationInHistory } from "./confirmation.ts"

const CONFIRMATION_TTL_MS = 5 * 60 * 1000

function extractTextContent(content: string | ChatCompletionMessage["content"]): string {
  if (content === null) return ""
  if (typeof content === "string") return content
  return content.map((p) => p.text ?? "").join("")
}

function wrapMessagesWithCategory(messages: ChatCompletionMessage[]): ChatCompletionMessage[] {
  const wrapped: ChatCompletionMessage[] = []
  for (const msg of messages) {
    if (msg.role === "user" || msg.role === "assistant") {
      const text = extractTextContent(msg.content)
      const category = msg.role === "user" ? "USER_MESSAGE" : "RESPOND"
      wrapped.push({
        role: msg.role,
        content: JSON.stringify({ topic: "conversation", category, content: text }),
      })
    } else {
      wrapped.push(msg)
    }
  }
  return wrapped
}

function mergeResponseFormat(
  request: ChatCompletionRequest,
  agentFormat?: { type: string }
): ChatCompletionRequest {
  if (!agentFormat) return request
  if (request.response_format) return request
  return { ...request, response_format: agentFormat }
}

function injectMetadata(
  request: ChatCompletionRequest,
  traceId: string,
  deviceKey?: string
): ChatCompletionRequest {
  const metadata: Record<string, unknown> = {
    ...request.metadata,
    arbiteros_trace_id: traceId,
  }
  if (deviceKey) {
    metadata.arbiteros_device_key = deviceKey
  }
  return { ...request, metadata }
}

export async function executePreCall(
  request: ChatCompletionRequest,
  config: ProxyConfig,
  pendingConfirmations: Map<string, ConfirmationEntry>
): Promise<PreCallResult> {
  const metadata = request.metadata ?? {}
  let traceId: string
  if (typeof metadata.arbiteros_trace_id === "string" && metadata.arbiteros_trace_id) {
    traceId = metadata.arbiteros_trace_id
  } else {
    traceId = crypto.randomUUID()
  }

  if (isPolicyConfirmationReply(request.messages)) {
    const reply = extractConfirmationReply(request.messages)
    const entry = pendingConfirmations.get(traceId)

    if (entry) {
      if (Date.now() - entry.createdAt >= CONFIRMATION_TTL_MS) {
        pendingConfirmations.delete(traceId)
        return {
          shouldBypass: true,
          bypassResponse: {
            id: `chatcmpl-${crypto.randomUUID()}`,
            object: "chat.completion",
            created: Math.floor(Date.now() / 1000),
            model: request.model,
            choices: [
              {
                index: 0,
                message: {
                  role: "assistant",
                  content: "确认已过期，请重新发起请求。",
                },
                finish_reason: "stop",
              },
            ],
          },
          traceId,
        }
      }

      const requestToken = typeof metadata.confirmation_token === "string" ? metadata.confirmation_token : null
      if (!requestToken || requestToken !== entry.token) {
        return {
          shouldBypass: true,
          bypassResponse: {
            id: `chatcmpl-${crypto.randomUUID()}`,
            object: "chat.completion",
            created: Math.floor(Date.now() / 1000),
            model: request.model,
            choices: [
              {
                index: 0,
                message: {
                  role: "assistant",
                  content: "确认令牌无效，操作被拒绝。",
                },
                finish_reason: "stop",
              },
            ],
          },
          traceId,
        }
      }

      if (reply === "no") {
        pendingConfirmations.delete(traceId)
        return {
          shouldBypass: true,
          bypassResponse: {
            id: `chatcmpl-${crypto.randomUUID()}`,
            object: "chat.completion",
            created: Math.floor(Date.now() / 1000),
            model: request.model,
            choices: [
              {
                index: 0,
                message: {
                  role: "assistant",
                  content: "操作已取消。",
                },
                finish_reason: "stop",
              },
            ],
          },
          traceId,
        }
      }

      if (reply === "yes") {
        pendingConfirmations.delete(traceId)
        return {
          shouldBypass: false,
          traceId,
          modifiedRequest: request,
        }
      }
    }
  }

  let modifiedRequest = { ...request }

  modifiedRequest = injectMetadata(modifiedRequest, traceId)

  modifiedRequest = wrapMessagesWithCategoryWrapper(modifiedRequest)

  return {
    shouldBypass: false,
    traceId,
    modifiedRequest,
  }
}

function wrapMessagesWithCategoryWrapper(request: ChatCompletionRequest): ChatCompletionRequest {
  const hasWrapper = request.messages.some((msg) => {
    if (msg.role !== "user" && msg.role !== "assistant") return false
    const text = extractTextContent(msg.content)
    try {
      const parsed = JSON.parse(text)
      return parsed.topic && parsed.category && parsed.content !== undefined
    } catch {
      return false
    }
  })

  if (hasWrapper) return request

  const wrapped = wrapMessagesWithCategory(request.messages)
  return { ...request, messages: wrapped }
}

export function parseTraceIdFromMetadata(metadata: Record<string, unknown> | undefined): string {
  if (metadata && typeof metadata.arbiteros_trace_id === "string" && metadata.arbiteros_trace_id) {
    return metadata.arbiteros_trace_id
  }
  return crypto.randomUUID()
}
