import type { ChatCompletionResponse, StreamingChunk, StreamingToolCall, ProxyConfig } from "./types.ts"
import type { Instruction } from "../types/instruction.ts"
import { executePostCall } from "./post-call.ts"
import { createConfirmationPrompt } from "./confirmation.ts"

function parseSSELine(line: string): { data: string } | null {
  if (!line.startsWith("data: ")) return null
  const data = line.slice(6).trim()
  if (data === "[DONE]") return { data: "[DONE]" }
  return { data }
}

function parseChunk(data: string): StreamingChunk | null {
  if (data === "[DONE]") return null
  try {
    return JSON.parse(data) as StreamingChunk
  } catch {
    return null
  }
}

interface AccumulatedResponse {
  id: string
  model: string
  content: string
  toolCalls: Map<number, { id: string; name: string; arguments: string }>
  finishReason: string | null
}

function createAccumulatedResponse(): AccumulatedResponse {
  return {
    id: "",
    model: "",
    content: "",
    toolCalls: new Map(),
    finishReason: null,
  }
}

function accumulateChunk(acc: AccumulatedResponse, chunk: StreamingChunk): void {
  if (!acc.id && chunk.id) acc.id = chunk.id
  if (!acc.model && chunk.model) acc.model = chunk.model

  for (const choice of chunk.choices) {
    if (choice.delta.content) {
      acc.content += choice.delta.content
    }
    if (choice.delta.tool_calls) {
      for (const tc of choice.delta.tool_calls) {
        const idx = tc.index ?? 0
        const existing = acc.toolCalls.get(idx) ?? {
          id: "",
          name: "",
          arguments: "",
        }
        if (tc.id) existing.id = tc.id
        if (tc.function?.name) existing.name = tc.function.name
        if (tc.function?.arguments) existing.arguments += tc.function.arguments
        acc.toolCalls.set(idx, existing)
      }
    }
    if (choice.finish_reason) {
      acc.finishReason = choice.finish_reason
    }
  }
}

function accumulatedToResponse(acc: AccumulatedResponse): ChatCompletionResponse {
  const toolCalls = Array.from(acc.toolCalls.entries())
    .sort(([a], [b]) => a - b)
    .map(([, tc]) => ({
      id: tc.id || `call_${crypto.randomUUID()}`,
      type: "function" as const,
      function: {
        name: tc.name,
        arguments: tc.arguments,
      },
    }))

  return {
    id: acc.id || `chatcmpl-${crypto.randomUUID()}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: acc.model,
    choices: [
      {
        index: 0,
        message: {
          role: "assistant",
          content: acc.content || null,
          tool_calls: toolCalls.length > 0 ? toolCalls : undefined,
        },
        finish_reason: acc.finishReason || "stop",
      },
    ],
  }
}

export async function processStreamingResponse(
  upstreamResponse: Response,
  traceId: string,
  config: ProxyConfig,
  previousInstructions: Instruction[],
  pendingConfirmations: Map<string, string>
): Promise<Response> {
  const reader = upstreamResponse.body?.getReader()
  if (!reader) {
    return new Response("Upstream response has no body", { status: 500 })
  }

  const decoder = new TextDecoder()
  const encoder = new TextEncoder()
  const accumulated = createAccumulatedResponse()

  let buffer = ""
  let policyChecked = false

  const transformStream = new TransformStream({
    async transform(chunk, controller) {
      buffer += decoder.decode(chunk, { stream: true })
      const lines = buffer.split("\n")
      buffer = lines.pop() ?? ""

      for (const line of lines) {
        if (!line.trim()) continue

        const parsed = parseSSELine(line)
        if (!parsed) continue

        if (parsed.data === "[DONE]") {
          if (!policyChecked) {
            policyChecked = true
            const fullResponse = accumulatedToResponse(accumulated)
            const postResult = await executePostCall(
              fullResponse,
              traceId,
              config,
              previousInstructions,
              pendingConfirmations
            )

            if (postResult.policyBlocked && postResult.policyMessage) {
              const confirmationMsg = createConfirmationPrompt(postResult.policyMessage)
              const policyChunk: StreamingChunk = {
                id: fullResponse.id,
                object: "chat.completion.chunk",
                created: Math.floor(Date.now() / 1000),
                model: fullResponse.model,
                choices: [
                  {
                    index: 0,
                    delta: { content: "\n\n---\n\n" + confirmationMsg },
                    finish_reason: null,
                  },
                ],
              }
              controller.enqueue(encoder.encode(`data: ${JSON.stringify(policyChunk)}\n\n`))
            }
          }

          controller.enqueue(encoder.encode("data: [DONE]\n\n"))
          continue
        }

        const chunk = parseChunk(parsed.data)
        if (chunk) {
          accumulateChunk(accumulated, chunk)
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`))
        }
      }
    },

    async flush(controller) {
      if (buffer.trim()) {
        const parsed = parseSSELine(buffer)
        if (parsed && parsed.data !== "[DONE]") {
          const chunk = parseChunk(parsed.data)
          if (chunk) {
            accumulateChunk(accumulated, chunk)
            controller.enqueue(encoder.encode(`data: ${JSON.stringify(chunk)}\n\n`))
          }
        }
      }

      if (!policyChecked) {
        policyChecked = true
        const fullResponse = accumulatedToResponse(accumulated)
        const postResult = await executePostCall(
          fullResponse,
          traceId,
          config,
          previousInstructions,
          pendingConfirmations
        )

        if (postResult.policyBlocked && postResult.policyMessage) {
          const confirmationMsg = createConfirmationPrompt(postResult.policyMessage)
          const policyChunk: StreamingChunk = {
            id: fullResponse.id,
            object: "chat.completion.chunk",
            created: Math.floor(Date.now() / 1000),
            model: fullResponse.model,
            choices: [
              {
                index: 0,
                delta: { content: "\n\n---\n\n" + confirmationMsg },
                finish_reason: null,
              },
            ],
          }
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(policyChunk)}\n\n`))
        }
      }

      controller.enqueue(encoder.encode("data: [DONE]\n\n"))
    },
  })

  return new Response(upstreamResponse.body?.pipeThrough(transformStream), {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  })
}

export function createStreamingChunk(
  id: string,
  model: string,
  content: string,
  finishReason: string | null = null
): string {
  const chunk: StreamingChunk = {
    id,
    object: "chat.completion.chunk",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [
      {
        index: 0,
        delta: { content },
        finish_reason: finishReason,
      },
    ],
  }
  return `data: ${JSON.stringify(chunk)}\n\n`
}
