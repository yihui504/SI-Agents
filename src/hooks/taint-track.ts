import type { AfterLLMContext } from "../types/hooks.ts"
import type { TaintTracker } from "../taint/tracker.ts"
import type { ToolCall, Instruction } from "../types/instruction.ts"
import { parseToolInstruction } from "../instruction/tool-parsers.ts"

export interface TaintTrackHookConfig {
  taintTracker: TaintTracker
  traceId: string
}

export function createTaintTrackHook(config: TaintTrackHookConfig): (ctx: AfterLLMContext) => Promise<void> {
  return async (ctx: AfterLLMContext): Promise<void> => {
    const toolCalls = extractToolCallsFromResponse(ctx.response)
    
    for (const toolCall of toolCalls) {
      const instruction = findOrCreateInstruction(toolCall, ctx.instructions, ctx.iteration)
      
      config.taintTracker.setBaseTaint(instruction, toolCall.tool_name, toolCall.arguments)
      
      const parseResult = parseToolInstruction(toolCall.tool_name, toolCall.arguments)
      
      const securityType = instruction["security_type"] as Record<string, unknown>
      if (securityType && typeof securityType === "object") {
        if (parseResult.securityType.confidentiality) {
          securityType["confidentiality"] = parseResult.securityType.confidentiality
        }
        if (parseResult.securityType.trustworthiness) {
          securityType["trustworthiness"] = parseResult.securityType.trustworthiness
        }
        if (parseResult.securityType.confidence) {
          securityType["confidence"] = parseResult.securityType.confidence
        }
        if (parseResult.securityType.reversible !== undefined) {
          securityType["reversible"] = parseResult.securityType.reversible
        }
        if (parseResult.securityType.authority) {
          securityType["authority"] = parseResult.securityType.authority
        }
      }
      
      instruction["instruction_type"] = parseResult.instructionType
      instruction["instruction_category"] = parseResult.instructionCategory
    }
    
    if (ctx.instructions.length > 0) {
      config.taintTracker.propagate(ctx.instructions)
    }
  }
}

function extractToolCallsFromResponse(response: Record<string, unknown>): ToolCall[] {
  const toolCalls: ToolCall[] = []
  
  const toolCallsArray = response["tool_calls"]
  if (Array.isArray(toolCallsArray)) {
    for (const tc of toolCallsArray) {
      if (tc && typeof tc === "object" && "tool_name" in tc && "tool_call_id" in tc) {
        toolCalls.push({
          tool_name: String(tc.tool_name),
          tool_call_id: String(tc.tool_call_id),
          arguments: (tc.arguments as Record<string, unknown>) || {},
          result: tc.result as string | undefined,
        })
      }
    }
  }
  
  const content = response["content"]
  if (typeof content === "string") {
    const pattern = /\{[^{}]*"tool_name"[^{}]*\}/g
    let match
    while ((match = pattern.exec(content)) !== null) {
      try {
        const parsed = JSON.parse(match[0])
        if (parsed.tool_name && parsed.tool_call_id) {
          const exists = toolCalls.some(tc => tc.tool_call_id === parsed.tool_call_id)
          if (!exists) {
            toolCalls.push({
              tool_name: String(parsed.tool_name),
              tool_call_id: String(parsed.tool_call_id),
              arguments: (parsed.arguments as Record<string, unknown>) || {},
            })
          }
        }
      } catch {
        continue
      }
    }
  }
  
  return toolCalls
}

function findOrCreateInstruction(
  toolCall: ToolCall,
  instructions: Instruction[],
  iteration: number
): Record<string, unknown> {
  const existing = instructions.find(
    instr => instr.content && 
    typeof instr.content === "object" &&
    "tool_call_id" in instr.content &&
    instr.content.tool_call_id === toolCall.tool_call_id
  )
  
  if (existing) {
    return existing as unknown as Record<string, unknown>
  }
  
  const newInstruction: Record<string, unknown> = {
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
  
  instructions.push(newInstruction as unknown as Instruction)
  
  return newInstruction
}
