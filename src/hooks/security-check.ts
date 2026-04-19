import type { BeforeLLMResult, BeforeLLMContext, BeforeToolContext, BeforeToolResult } from "../types/hooks.ts"
import type { PolicyRegistry } from "../policy/registry.ts"
import type { TaintTracker } from "../taint/tracker.ts"
import type { ToolCall } from "../types/instruction.ts"
import type { RateLimiter, RateLimitConfig } from "../policy/rate-limiter.ts"

export interface SecurityCheckHookConfig {
  policyRegistry: PolicyRegistry
  taintTracker: TaintTracker
  traceId: string
  rateLimiter?: RateLimiter
  rateLimitKeyGenerator?: (ctx: BeforeToolContext) => string
}

/**
 * 默认的速率限制键生成器
 * 使用工具名称作为键
 */
function defaultRateLimitKeyGenerator(ctx: BeforeToolContext): string {
  return `tool:${ctx.toolCall.tool_name}`
}

/**
 * 创建安全检查 hook（用于 beforeLLM）
 */
export function createSecurityCheckHook(config: SecurityCheckHookConfig): (ctx: BeforeLLMContext) => Promise<BeforeLLMResult> {
  return async (ctx: BeforeLLMContext): Promise<BeforeLLMResult> => {
    const toolCalls = extractToolCallsFromPrompt(ctx.prompt)
    
    if (toolCalls.length === 0) {
      return { action: "passthrough" }
    }

    const policies = config.policyRegistry.getEnabledPolicies()
    
    for (const toolCall of toolCalls) {
      const instruction = createInstructionFromToolCall(toolCall, ctx.iteration)
      
      for (const policy of policies) {
        const result = await policy.check(
          [],
          { tool_calls: [toolCall] },
          [instruction],
          config.traceId
        )
        
        if (result.error_type) {
          return {
            action: "block",
            reason: `Policy blocked tool "${toolCall.tool_name}": ${result.error_type}`
          }
        }
      }
    }
    
    return { action: "passthrough" }
  }
}

/**
 * 创建速率限制检查 hook（用于 beforeTool）
 */
export function createRateLimitHook(config: SecurityCheckHookConfig): (ctx: BeforeToolContext) => Promise<BeforeToolResult> {
  const keyGenerator = config.rateLimitKeyGenerator || defaultRateLimitKeyGenerator
  
  return async (ctx: BeforeToolContext): Promise<BeforeToolResult> => {
    // 如果没有配置速率限制器，直接通过
    if (!config.rateLimiter) {
      return { action: "passthrough" }
    }

    const key = keyGenerator(ctx)
    const result = config.rateLimiter.checkLimit(key)

    if (!result.allowed) {
      const retryAfterMsg = result.retryAfter 
        ? ` (retry after ${result.retryAfter} seconds)` 
        : ""
      return {
        action: "block",
        reason: `Rate limit exceeded for "${ctx.toolCall.tool_name}"${retryAfterMsg}. Remaining: ${result.remaining}, Reset at: ${new Date(result.resetTime).toISOString()}`
      }
    }

    return { action: "passthrough" }
  }
}

/**
 * 创建组合的安全检查 hook（包含策略检查和速率限制）
 */
export function createCombinedSecurityHook(config: SecurityCheckHookConfig): (ctx: BeforeToolContext) => Promise<BeforeToolResult> {
  const rateLimitHook = createRateLimitHook(config)
  
  return async (ctx: BeforeToolContext): Promise<BeforeToolResult> => {
    // 首先检查速率限制
    const rateLimitResult = await rateLimitHook(ctx)
    if (rateLimitResult.action === "block") {
      return rateLimitResult
    }

    // 然后进行策略检查
    const policies = config.policyRegistry.getEnabledPolicies()
    const instruction = createInstructionFromToolCall(ctx.toolCall, ctx.iteration)
    
    for (const policy of policies) {
      const result = await policy.check(
        [],
        { tool_calls: [ctx.toolCall] },
        [instruction],
        config.traceId
      )
      
      if (result.error_type) {
        return {
          action: "block",
          reason: `Policy blocked tool "${ctx.toolCall.tool_name}": ${result.error_type}`
        }
      }
    }

    return { action: "passthrough" }
  }
}

function extractToolCallsFromPrompt(prompt: string): ToolCall[] {
  const toolCalls: ToolCall[] = []
  const toolCallPattern = /<tool_call[^>]*>([\s\S]*?)<\/tool_call>/gi
  let match
  
  while ((match = toolCallPattern.exec(prompt)) !== null) {
    try {
      const content = match[1].trim()
      const parsed = JSON.parse(content)
      if (parsed.tool_name && parsed.tool_call_id) {
        toolCalls.push({
          tool_name: parsed.tool_name,
          tool_call_id: parsed.tool_call_id,
          arguments: parsed.arguments || {},
        })
      }
    } catch {
      continue
    }
  }
  
  const jsonPattern = /\{[^{}]*"tool_name"[^{}]*\}/g
  while ((match = jsonPattern.exec(prompt)) !== null) {
    try {
      const parsed = JSON.parse(match[0])
      if (parsed.tool_name && parsed.tool_call_id) {
        const exists = toolCalls.some(tc => tc.tool_call_id === parsed.tool_call_id)
        if (!exists) {
          toolCalls.push({
            tool_name: parsed.tool_name,
            tool_call_id: parsed.tool_call_id,
            arguments: parsed.arguments || {},
          })
        }
      }
    } catch {
      continue
    }
  }
  
  return toolCalls
}

function createInstructionFromToolCall(toolCall: ToolCall, iteration: number): Record<string, unknown> {
  return {
    id: crypto.randomUUID(),
    content: toolCall,
    runtime_step: iteration,
    parent_id: null,
    source_message_id: null,
    security_type: {
      confidentiality: "UNKNOWN",
      trustworthiness: "UNKNOWN",
      prop_confidentiality: "UNKNOWN",
      prop_trustworthiness: "UNKNOWN",
      confidence: "UNKNOWN",
      reversible: false,
      authority: "UNKNOWN",
      risk: "UNKNOWN",
      custom: {},
    },
    rule_types: [],
    instruction_category: "EXECUTION.Env",
    instruction_type: "EXEC",
  }
}
