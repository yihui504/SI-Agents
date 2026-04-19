export interface ChatCompletionRequest {
  model: string
  messages: ChatCompletionMessage[]
  tools?: ToolDefinition[]
  response_format?: { type: string }
  stream?: boolean
  temperature?: number
  max_tokens?: number
  metadata?: Record<string, unknown>
}

export interface ChatCompletionMessage {
  role: "system" | "user" | "assistant" | "tool"
  content: string | ChatCompletionContentPart[] | null
  tool_calls?: ToolCall[]
  tool_call_id?: string
}

export interface ChatCompletionContentPart {
  type: "text" | "image_url"
  text?: string
  image_url?: { url: string }
}

export interface ChatCompletionResponse {
  id: string
  object: string
  created: number
  model: string
  choices: ChatCompletionChoice[]
  usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number }
}

export interface ChatCompletionChoice {
  index: number
  message: ChatCompletionMessage
  finish_reason: string
}

export interface ToolCall {
  id: string
  type: "function"
  function: { name: string; arguments: string }
}

export interface ToolDefinition {
  type: "function"
  function: { name: string; description: string; parameters: object }
}

export interface StreamingChunk {
  id: string
  object: string
  created: number
  model: string
  choices: StreamingChoice[]
}

export interface StreamingToolCall {
  index?: number
  id?: string
  type?: "function"
  function?: { name?: string; arguments?: string }
}

export interface StreamingChoice {
  index: number
  delta: { role?: string; content?: string; tool_calls?: StreamingToolCall[] }
  finish_reason: string | null
}

export interface ProxyConfig {
  policyRegistry: import("../policy/registry.ts").PolicyRegistry
  taintTracker: import("../taint/tracker.ts").TaintTracker
  modelRoutes: Map<string, import("../types/config.ts").ModelRoute>
  defaultModel?: string
  observeOnly: boolean
  securityDir: string
  output_budget?: {
    max_chars?: number
  }
}

export interface PreCallResult {
  shouldBypass: boolean
  bypassResponse?: ChatCompletionResponse
  traceId: string
  modifiedRequest?: ChatCompletionRequest
}

export interface PostCallResult {
  modified: boolean
  response: ChatCompletionResponse
  policyBlocked: boolean
  policyMessage?: string
}

export interface TraceContext {
  traceId: string
  request: ChatCompletionRequest
  response?: ChatCompletionResponse
  instructions: import("../types/instruction.ts").Instruction[]
  startTime: number
}

export interface OpenAIError {
  error: {
    message: string
    type: string
    param: string | null
    code: string
  }
}
