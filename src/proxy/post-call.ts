import type { ChatCompletionResponse, ChatCompletionMessage, PostCallResult, ToolCall, ConfirmationEntry } from "./types.ts"
import type { ProxyConfig } from "./types.ts"
import type { Instruction } from "../types/instruction.ts"
import { InstructionBuilder } from "../instruction/builder.ts"
import { checkResponsePolicy } from "../policy/check.ts"
import { createConfirmationPrompt, createMockResponse } from "./confirmation.ts"

function extractResponseContent(response: ChatCompletionResponse): string {
  const choice = response.choices[0]
  if (!choice) return ""

  const message = choice.message
  if (message.content) {
    const text = typeof message.content === "string" ? message.content : ""
    try {
      const parsed = JSON.parse(text)
      if (parsed.topic && parsed.category && parsed.content !== undefined) {
        return parsed.content
      }
    } catch {
      // Not wrapped format
    }
    return text
  }

  return ""
}

function unwrapResponse(response: ChatCompletionResponse): ChatCompletionResponse {
  const choice = response.choices[0]
  if (!choice) return response

  const message = choice.message
  if (!message.content) return response

  const text = typeof message.content === "string" ? message.content : ""
  try {
    const parsed = JSON.parse(text)
    if (parsed.topic && parsed.category && parsed.content !== undefined) {
      return {
        ...response,
        choices: [
          {
            ...choice,
            message: {
              ...message,
              content: parsed.content,
            },
          },
        ],
      }
    }
  } catch {
    // Not wrapped format
  }

  return response
}

function parseInstructionsFromResponse(
  response: ChatCompletionResponse,
  traceId: string
): Instruction[] {
  const builder = new InstructionBuilder(traceId, "openclaw")
  const choice = response.choices[0]
  if (!choice) return []

  const message = choice.message

  if (message.content) {
    const text = typeof message.content === "string" ? message.content : ""
    try {
      const parsed = JSON.parse(text)
      if (parsed.category || parsed.intent) {
        builder.addFromStructuredOutput(parsed)
      } else if (parsed.topic && parsed.content) {
        builder.addFromStructuredOutput({
          category: parsed.category,
          content: parsed.content,
        })
      }
    } catch {
      if (text.trim()) {
        builder.addFromStructuredOutput({ content: text })
      }
    }
  }

  if (message.tool_calls) {
    for (const tc of message.tool_calls) {
      let args: Record<string, unknown> = {}
      try {
        args = JSON.parse(tc.function.arguments)
      } catch {
        args = {}
      }
      builder.addFromToolCall(tc.function.name, tc.id, args)
    }
  }

  builder.commit()
  return builder.getInstructions()
}

export async function executePostCall(
  response: ChatCompletionResponse,
  traceId: string,
  config: ProxyConfig,
  previousInstructions: Instruction[],
  pendingConfirmations: Map<string, ConfirmationEntry>
): Promise<PostCallResult> {
  const unwrappedResponse = unwrapResponse(response)

  // Check output budget before policy check
  const maxChars = config.output_budget?.max_chars
  if (maxChars && maxChars > 0) {
    const content = extractResponseContent(unwrappedResponse)
    if (content.length > maxChars) {
      const truncatedContent = content.slice(0, maxChars)
      const warningMessage = `## ⚠️ 输出长度超限\n\n响应内容已超过最大字符限制 (${maxChars} 字符)，已被截断。\n\n---\n\n${truncatedContent}`
      
      return {
        modified: true,
        response: createMockResponse(warningMessage, response.model),
        policyBlocked: true,
        policyMessage: `输出长度 ${content.length} 超过最大限制 ${maxChars}`,
      }
    }
  }

  const newInstructions = parseInstructionsFromResponse(unwrappedResponse, traceId)
  const allInstructions = [...previousInstructions, ...newInstructions]

  const latestInstructions = newInstructions

  const responseRecord: Record<string, unknown> = {
    id: response.id,
    model: response.model,
    choices: response.choices.map((c) => ({
      index: c.index,
      message: {
        role: c.message.role,
        content: c.message.content,
        tool_calls: c.message.tool_calls,
      },
      finish_reason: c.finish_reason,
    })),
  }

  const policyResult = await checkResponsePolicy(
    traceId,
    allInstructions.map((i) => i as unknown as Record<string, unknown>),
    responseRecord,
    latestInstructions.map((i) => i as unknown as Record<string, unknown>),
    config.policyRegistry
  )

  if (policyResult.error_type && !config.observeOnly) {
    const blockedMessage = policyResult.error_type
    const token = crypto.randomUUID()
    pendingConfirmations.set(traceId, { message: blockedMessage, token, createdAt: Date.now() })

    const confirmationMessage = createConfirmationPrompt(blockedMessage)

    const mockResponse = createMockResponse(confirmationMessage, response.model)
    return {
      modified: true,
      response: { ...mockResponse, confirmation_token: token },
      policyBlocked: true,
      policyMessage: blockedMessage,
    }
  }

  return {
    modified: policyResult.modified,
    response: unwrappedResponse,
    policyBlocked: false,
    policyMessage: policyResult.error_type ?? undefined,
  }
}

export function extractToolCallsFromResponse(response: ChatCompletionResponse): ToolCall[] {
  const choice = response.choices[0]
  if (!choice || !choice.message.tool_calls) return []
  return choice.message.tool_calls
}

export function hasToolCalls(response: ChatCompletionResponse): boolean {
  const choice = response.choices[0]
  return !!(choice && choice.message.tool_calls && choice.message.tool_calls.length > 0)
}
