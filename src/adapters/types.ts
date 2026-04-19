import type { ToolCall, Instruction } from "../types/instruction.ts"
import type {
  RuntimeHooks,
  BeforeLLMContext as BaseBeforeLLMContext,
  BeforeLLMResult,
  AfterLLMContext as BaseAfterLLMContext,
  BeforeToolContext as BaseBeforeToolContext,
  BeforeToolResult,
  AfterToolContext as BaseAfterToolContext,
  AfterRunContext as BaseAfterRunContext,
} from "../types/hooks.ts"

export type {
  RuntimeHooks,
  BeforeLLMResult,
  BeforeToolResult,
}

export interface AdapterConfig {
  model: string
  apiKey?: string
  baseUrl?: string
  maxSteps?: number
  timeoutMs?: number
}

export interface AgentAdapter {
  readonly name: string
  setup(config: AdapterConfig): Promise<void>
  run(config: AdapterRunConfig): Promise<AdapterRunResult>
  setHooks(hooks: RuntimeHooks): void
  teardown(): Promise<void>
}

export interface BeforeLLMContext extends BaseBeforeLLMContext {}

export interface AfterLLMContext extends Omit<BaseAfterLLMContext, "response"> {
  response: LLMResponse
}

export interface BeforeToolContext extends BaseBeforeToolContext {}

export interface AfterToolContext extends BaseAfterToolContext {}

export interface AfterRunContext extends Omit<BaseAfterRunContext, "result"> {
  result: AdapterRunResult
}

export interface AdapterRunConfig {
  prompt: string
  workDir: string
  skillContent?: string
  skillMode?: SkillMode
  skillMeta?: { name: string; description: string }
  taskId?: string
  timeoutMs?: number
}

export type SkillMode = "inject" | "discover"

export type RunStatus = "ok" | "timeout" | "adapter-crashed" | "policy-blocked"

export interface AdapterRunResult {
  text: string
  steps: AgentStep[]
  tokens: TokenUsage
  cost: number
  durationMs: number
  llmDurationMs: number
  workDir: string
  skillLoaded?: boolean
  runStatus: RunStatus
  statusDetail?: string
  adapterError?: { exitCode: number; stderr: string }
}

export interface AgentStep {
  role: "assistant" | "tool"
  text?: string
  toolCalls?: ToolCall[]
  timestamp: number
}

export interface TokenUsage {
  input: number
  output: number
}

export interface LLMResponse {
  text: string
  toolCalls: LLMToolCall[]
  tokens: TokenUsage
  costUsd?: number
  durationMs: number
  stopReason: "end_turn" | "tool_use" | "max_tokens" | "stop_sequence"
}

export interface LLMToolCall {
  id: string
  name: string
  arguments: Record<string, unknown>
}

export interface LLMTool {
  name: string
  description: string
  inputSchema: Record<string, unknown>
}

export interface LLMMessage {
  role: "system" | "user" | "assistant"
  content: string
}

export interface LLMToolResult {
  toolCallId: string
  content: string
  isError?: boolean
}

export interface CompletionParams {
  messages: LLMMessage[]
  system?: string
  tools?: LLMTool[]
  toolChoice?: ToolChoice
  maxTokens?: number
  temperature?: number
  stopSequences?: string[]
}

export type ToolChoice = "auto" | "required" | { name: string }

export interface LLMProvider {
  readonly name: string
  complete(params: CompletionParams): Promise<LLMResponse>
  completeWithToolResults(
    params: CompletionParams,
    toolResults: LLMToolResult[],
    previousResponse: LLMResponse,
  ): Promise<LLMResponse>
}

export interface ToolResult {
  output: string
  exitCode?: number
  durationMs: number
}

export function emptyTokenUsage(): TokenUsage {
  return { input: 0, output: 0 }
}

export function addTokenUsage(a: TokenUsage, b: TokenUsage): TokenUsage {
  return {
    input: a.input + b.input,
    output: a.output + b.output,
  }
}
