import type { ToolCall, Instruction } from "./instruction.ts"

export interface BeforeLLMContext {
  prompt: string
  workDir: string
  iteration: number
  previousToolCalls: ToolCall[]
}

export type BeforeLLMResult =
  | { action: "passthrough" }
  | { action: "replace"; toolResults: ToolCall[]; text?: string }
  | { action: "block"; reason: string }

export interface AfterLLMContext {
  response: Record<string, unknown>
  iteration: number
  workDir: string
  instructions: Instruction[]
}

export interface AfterToolContext {
  toolCall: ToolCall
  workDir: string
  iteration: number
}

export interface BeforeToolContext {
  toolCall: ToolCall
  workDir: string
  iteration: number
}

export type BeforeToolResult =
  | { action: "passthrough" }
  | { action: "block"; reason: string }

export interface AfterRunContext {
  result: Record<string, unknown>
  skillId?: string
  success: boolean
}

export interface RuntimeHooks {
  beforeLLM?: Array<(ctx: BeforeLLMContext) => Promise<BeforeLLMResult>>
  afterLLM?: Array<(ctx: AfterLLMContext) => Promise<void>>
  beforeTool?: Array<(ctx: BeforeToolContext) => Promise<BeforeToolResult>>
  afterTool?: Array<(ctx: AfterToolContext) => Promise<void>>
  afterRun?: Array<(ctx: AfterRunContext) => Promise<void>>
}
