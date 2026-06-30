import path from "node:path"
import { mkdir } from "node:fs/promises"
import type {
  AgentAdapter,
  AdapterConfig,
  AdapterRunConfig,
  AdapterRunResult,
  LLMProvider,
  LLMTool,
  LLMToolCall,
  LLMToolResult,
  LLMResponse,
  LLMMessage,
  CompletionParams,
  ToolResult,
  AgentStep,
  TokenUsage,
} from "./types.ts"
import { emptyTokenUsage, addTokenUsage } from "./types.ts"
import { AGENT_TOOLS, createToolExecutor } from "./bare-agent-tools.ts"
import type { ToolCall, Instruction } from "../types/instruction.ts"
import type {
  RuntimeHooks,
  BeforeLLMContext,
  BeforeLLMResult,
  AfterLLMContext,
  BeforeToolContext,
  BeforeToolResult,
  AfterToolContext,
  AfterRunContext,
} from "../types/hooks.ts"
import { traceManager } from "./trace-manager.ts"
import { confirmationHandler } from "./confirmation-handler.ts"
import { checkSSRF, DEFAULT_SSRF_CONFIG } from "../utils/ssrf-guard.ts"
import type { SSRFGuardConfig } from "../utils/ssrf-guard.ts"

const DEFAULT_MAX_STEPS = 50
const DEFAULT_TIMEOUT_MS = 300_000
const DEFAULT_MAX_TOKENS = 16384

const LIST_DIRECTORY_TOOL: LLMTool = {
  name: "list_directory",
  description: "List files and directories at the given path relative to the working directory.",
  inputSchema: {
    type: "object",
    properties: { path: { type: "string", description: "Relative directory path (default: '.')" } },
  },
}

const WEB_FETCH_TOOL: LLMTool = {
  name: "web_fetch",
  description: "Fetch a URL and return the response body. Supports GET and POST.",
  inputSchema: {
    type: "object",
    properties: {
      url: { type: "string", description: "URL to fetch" },
      method: { type: "string", description: "HTTP method (default: GET)" },
      headers: { type: "object", description: "Request headers" },
      body: { type: "string", description: "Request body (for POST)" },
    },
    required: ["url"],
  },
}

const TOOLS: LLMTool[] = [...AGENT_TOOLS]

const LOAD_SKILL_RE = /<?load-skill>\s*(.*?)\s*<\/load-skill>/

async function copySkillToDiscoverDir(
  task: { skillContent: string; skillMeta: { name: string; description: string } },
  workDir: string,
): Promise<void> {
  const skillDir = path.join(workDir, "skills", task.skillMeta.name)
  await mkdir(skillDir, { recursive: true })
  await Bun.write(path.join(skillDir, "SKILL.md"), task.skillContent)
}

function estimateCost(
  model: string,
  tokens: TokenUsage,
  reportedCost?: number,
  modelPricing?: Record<string, { inputPrice: number; outputPrice: number }>,
): number {
  if (reportedCost !== undefined) return reportedCost

  const lowerModel = model.toLowerCase()

  if (modelPricing) {
    for (const key of Object.keys(modelPricing)) {
      if (lowerModel.includes(key.toLowerCase())) {
        const pricing = modelPricing[key]
        return tokens.input * pricing.inputPrice + tokens.output * pricing.outputPrice
      }
    }
  }

  let inputPrice = 0
  let outputPrice = 0

  if (lowerModel.includes("gpt-4o")) {
    inputPrice = 2.5 / 1_000_000
    outputPrice = 10 / 1_000_000
  } else if (lowerModel.includes("gpt-4-turbo")) {
    inputPrice = 10 / 1_000_000
    outputPrice = 30 / 1_000_000
  } else if (lowerModel.includes("gpt-4")) {
    inputPrice = 30 / 1_000_000
    outputPrice = 60 / 1_000_000
  } else if (lowerModel.includes("gpt-3.5-turbo")) {
    inputPrice = 0.5 / 1_000_000
    outputPrice = 1.5 / 1_000_000
  } else if (lowerModel.includes("claude-3-opus")) {
    inputPrice = 15 / 1_000_000
    outputPrice = 75 / 1_000_000
  } else if (lowerModel.includes("claude-3-sonnet")) {
    inputPrice = 3 / 1_000_000
    outputPrice = 15 / 1_000_000
  } else if (lowerModel.includes("claude-3-haiku")) {
    inputPrice = 0.25 / 1_000_000
    outputPrice = 1.25 / 1_000_000
  } else if (lowerModel.includes("glm-4.5-flash")) {
    inputPrice = 0.0001 / 1_000
    outputPrice = 0.0001 / 1_000
  } else if (lowerModel.includes("glm-4.7")) {
    inputPrice = 0.0005 / 1_000
    outputPrice = 0.0005 / 1_000
  } else if (lowerModel.includes("glm-4-plus")) {
    inputPrice = 50 / 1_000_000
    outputPrice = 50 / 1_000_000
  } else {
    inputPrice = 1 / 1_000_000
    outputPrice = 3 / 1_000_000
  }

  return tokens.input * inputPrice + tokens.output * outputPrice
}

function llmResponseToRecord(response: LLMResponse): Record<string, unknown> {
  const toolCalls = response.toolCalls.map(tc => ({
    tool_name: tc.name,
    tool_call_id: tc.id,
    arguments: tc.arguments,
  }))
  return {
    text: response.text,
    toolCalls: response.toolCalls,
    tool_calls: toolCalls,
    content: response.text || "",
    tokens: response.tokens,
    costUsd: response.costUsd,
    durationMs: response.durationMs,
    stopReason: response.stopReason,
  }
}

function runResultToRecord(result: AdapterRunResult): Record<string, unknown> {
  return {
    text: result.text,
    steps: result.steps,
    tokens: result.tokens,
    cost: result.cost,
    durationMs: result.durationMs,
    llmDurationMs: result.llmDurationMs,
    workDir: result.workDir,
    skillLoaded: result.skillLoaded,
    runStatus: result.runStatus,
    statusDetail: result.statusDetail,
    adapterError: result.adapterError,
  }
}

export class BareAgentAdapter implements AgentAdapter {
  readonly name = "bare-agent"
  private provider!: LLMProvider
  private model = ""
  private maxSteps = DEFAULT_MAX_STEPS
  private timeoutMs = DEFAULT_TIMEOUT_MS
  private modelPricing?: Record<string, { inputPrice: number; outputPrice: number }>
  private ssrfConfig: SSRFGuardConfig = { ...DEFAULT_SSRF_CONFIG }
  private hooks: RuntimeHooks = {}
  private providerFactory: (config: AdapterConfig) => LLMProvider
  private customTools: LLMTool[] = []
  private customToolExecutors: Map<string, (args: Record<string, unknown>) => Promise<string>> = new Map()

  constructor(
    providerFactory: (config: AdapterConfig) => LLMProvider,
    hooks?: RuntimeHooks,
  ) {
    this.providerFactory = providerFactory
    if (hooks) this.hooks = hooks
  }

  setHooks(hooks: RuntimeHooks): void {
    this.hooks = hooks
  }

  registerTool(tool: LLMTool): void {
    if (this.customTools.some(t => t.name === tool.name)) {
      console.warn(`Tool "${tool.name}" is already registered, skipping duplicate`)
      return
    }
    this.customTools.push(tool)
  }

  unregisterTool(toolName: string): boolean {
    const idx = this.customTools.findIndex(t => t.name === toolName)
    if (idx === -1) return false
    this.customTools.splice(idx, 1)
    return true
  }

  getTools(): LLMTool[] {
    return [...TOOLS, ...this.customTools]
  }

  registerToolExecutor(toolName: string, executor: (args: Record<string, unknown>) => Promise<string>): void {
    this.customToolExecutors.set(toolName, executor)
  }

  async setup(config: AdapterConfig): Promise<void> {
    this.provider = this.providerFactory(config)
    this.model = config.model
    if (config.maxSteps) this.maxSteps = config.maxSteps
    if (config.timeoutMs) this.timeoutMs = config.timeoutMs
    if (config.modelPricing) this.modelPricing = config.modelPricing
    if (config.ssrfGuard) this.ssrfConfig = { ...DEFAULT_SSRF_CONFIG, ...config.ssrfGuard }
  }

  async run(task: AdapterRunConfig): Promise<AdapterRunResult> {
    const startMs = performance.now()
    const skillMode = task.skillMode ?? "inject"
    const traceId = traceManager.createTrace()

    let activeProvider: LLMProvider = this.provider

    let skillLoaded = false
    let system = "You are a helpful assistant that completes tasks by using tools. Work in the provided directory."

    if (task.skillContent && skillMode === "inject") {
      system += `\n\n<skill>\n${task.skillContent}\n</skill>`
      skillLoaded = true
    } else if (task.skillContent && skillMode === "discover" && task.skillMeta) {
      await copySkillToDiscoverDir(
        { skillContent: task.skillContent, skillMeta: task.skillMeta },
        task.workDir,
      )
      const skillName = task.skillMeta.name
      system += `\n\n## Available Skills

You have access to domain-specific skills. To load a skill, respond with EXACTLY:

<load-skill>${skillName}</load-skill>

IMPORTANT: Replace "${skillName}" with the exact skill name from the list below. The opening <load-skill> and closing </load-skill> tags are both required.

Available skills:
- **${skillName}**: ${task.skillMeta.description}`
    }

    const beforeLLMHooks = this.hooks.beforeLLM
    const allToolCalls: ToolCall[] = []
    const instructions: Instruction[] = []

    let discoverSkillLoaded = skillLoaded

    const wrappedProvider: LLMProvider = {
      name: activeProvider.name,

      complete: async (params: CompletionParams): Promise<LLMResponse> => {
        if (beforeLLMHooks) {
          for (const hook of beforeLLMHooks) {
            const ctx: BeforeLLMContext = {
              prompt: task.prompt,
              workDir: task.workDir,
              iteration: 0,
              previousToolCalls: allToolCalls,
            }
            const result = await hook(ctx)
            if (result.action === "replace" && result.toolResults) {
              return {
                text: result.text ?? "Boosted execution",
                toolCalls: result.toolResults.map(tr => ({
                  name: tr.tool_name,
                  id: tr.tool_call_id,
                  arguments: tr.arguments as Record<string, unknown>,
                })),
                tokens: emptyTokenUsage(),
                durationMs: 0,
                stopReason: "tool_use",
              }
            }
            if (result.action === "block") {
              return {
                text: `Blocked by policy: ${result.reason}`,
                toolCalls: [],
                tokens: emptyTokenUsage(),
                durationMs: 0,
                stopReason: "end_turn",
              }
            }
          }
        }
        return activeProvider.complete(params)
      },

      completeWithToolResults: async (
        params: CompletionParams,
        toolResults: LLMToolResult[],
        prevResponse: LLMResponse,
      ): Promise<LLMResponse> => {
        if (beforeLLMHooks) {
          for (const hook of beforeLLMHooks) {
            const ctx: BeforeLLMContext = {
              prompt: task.prompt,
              workDir: task.workDir,
              iteration: 0,
              previousToolCalls: allToolCalls,
            }
            const result = await hook(ctx)
            if (result.action === "replace" && result.toolResults) {
              return {
                text: result.text ?? "Boosted execution",
                toolCalls: result.toolResults.map(tr => ({
                  name: tr.tool_name,
                  id: tr.tool_call_id,
                  arguments: tr.arguments as Record<string, unknown>,
                })),
                tokens: emptyTokenUsage(),
                durationMs: 0,
                stopReason: "tool_use",
              }
            }
            if (result.action === "block") {
              return {
                text: `Blocked by policy: ${result.reason}`,
                toolCalls: [],
                tokens: emptyTokenUsage(),
                durationMs: 0,
                stopReason: "end_turn",
              }
            }
          }
        }
        return activeProvider.completeWithToolResults(params, toolResults, prevResponse)
      },
    }

    const loopResult = await this.runAgentLoop(
      {
        provider: wrappedProvider,
        model: this.model,
        tools: this.getTools(),
        executeTool: async (call: LLMToolCall) => {
          const customExecutor = this.customToolExecutors.get(call.name)
          if (customExecutor) {
            const output = await customExecutor(call.arguments as Record<string, unknown>)
            return { output, durationMs: 0 }
          }
          if (call.name === "web_fetch") {
            const url = call.arguments.url as string | undefined
            if (url) {
              const ssrfResult = checkSSRF(url, this.ssrfConfig)
              if (!ssrfResult.allowed) {
                return { output: `SSRF protection: ${ssrfResult.reason}`, durationMs: 0 }
              }
            }
          }
          return createToolExecutor(task.workDir)(call)
        },
        system,
        maxIterations: this.maxSteps,
        timeoutMs: task.timeoutMs ?? this.timeoutMs,
        maxTokens: DEFAULT_MAX_TOKENS,
        traceId,
        instructions,
        onAfterLLM: async (response: LLMResponse, iteration: number) => {
          if (skillMode === "discover" && task.skillContent && task.skillMeta && !discoverSkillLoaded) {
            const skillMatch = response.text.match(LOAD_SKILL_RE)
            if (skillMatch) {
              const requestedName = (skillMatch[1] ?? "").trim()
              if (requestedName === task.skillMeta.name) {
                discoverSkillLoaded = true
                skillLoaded = true
              }
            }
          }
          if (this.hooks.afterLLM) {
            const ctx: AfterLLMContext = {
              response: llmResponseToRecord(response),
              iteration,
              workDir: task.workDir,
              instructions,
            }
            for (const hook of this.hooks.afterLLM) {
              await hook(ctx)
            }
          }
        },
        onAfterTool: this.hooks.afterTool
          ? async (completedCall: ToolCall, iteration: number) => {
              allToolCalls.push(completedCall)
              const ctx: AfterToolContext = {
                toolCall: completedCall,
                workDir: task.workDir,
                iteration,
              }
              for (const hook of this.hooks.afterTool!) {
                await hook(ctx)
              }
            }
          : (completedCall: ToolCall) => {
              allToolCalls.push(completedCall)
            },
        onBeforeTool: this.hooks.beforeTool
          ? async (toolCall: ToolCall, iteration: number): Promise<BeforeToolResult> => {
              const ctx: BeforeToolContext = {
                toolCall,
                workDir: task.workDir,
                iteration,
              }
              for (const hook of this.hooks.beforeTool!) {
                const result = await hook(ctx)
                if (result.action === "block") {
                  return result
                }
              }
              return { action: "passthrough" }
            }
          : undefined,
      },
      [{ role: "user", content: task.prompt }],
    )

    const durationMs = performance.now() - startMs

    const runStatus: AdapterRunResult["runStatus"] = loopResult.timedOut
      ? "timeout"
      : loopResult.error
        ? "adapter-crashed"
        : loopResult.policyRetryExceeded
          ? "policy-retry-exceeded"
          : loopResult.policyBlocked
            ? "policy-blocked"
            : "ok"

    const statusDetail = loopResult.timedOut
      ? `bare-agent loop exceeded timeout ${task.timeoutMs ?? this.timeoutMs}ms after ${loopResult.iterations} iterations`
      : loopResult.error
        ? loopResult.error.message.slice(0, 200)
        : loopResult.policyRetryExceeded
          ? `Policy retry limit exceeded (${loopResult.iterations} consecutive blocks)`
          : loopResult.policyBlocked
            ? "Blocked by policy"
            : undefined

    traceManager.endTrace(traceId, runStatus === "ok" ? "completed" : "failed", statusDetail)

    const runResult: AdapterRunResult = {
      text: loopResult.text,
      steps: loopResult.steps,
      tokens: loopResult.tokens,
      cost: estimateCost(this.model, loopResult.tokens, loopResult.totalCostUsd, this.modelPricing),
      durationMs,
      llmDurationMs: loopResult.llmDurationMs,
      workDir: task.workDir,
      skillLoaded: task.skillContent ? skillLoaded : undefined,
      runStatus,
      ...(statusDetail ? { statusDetail } : {}),
      ...(loopResult.error ? { adapterError: { exitCode: 1, stderr: loopResult.error.message } } : {}),
    }

    if (this.hooks.afterRun) {
      const ctx: AfterRunContext = {
        result: runResultToRecord(runResult),
        success: loopResult.text.length > 0,
      }
      for (const hook of this.hooks.afterRun) {
        await hook(ctx)
      }
    }

    return runResult
  }

  async teardown(): Promise<void> {
    // nothing to clean up
  }

  private async runAgentLoop(
    config: {
      provider: LLMProvider
      model: string
      tools: LLMTool[]
      executeTool: (call: LLMToolCall) => Promise<ToolResult>
      system: string
      maxIterations: number
      timeoutMs: number
      maxTokens?: number
      traceId: string
      instructions: Instruction[]
      onAfterLLM?: (response: LLMResponse, iteration: number) => Promise<void> | void
      onAfterTool?: (completedCall: ToolCall, iteration: number) => Promise<void> | void
      onBeforeTool?: (toolCall: ToolCall, iteration: number) => Promise<BeforeToolResult>
      maxPolicyRetries?: number
    },
    initialMessages: LLMMessage[],
  ): Promise<{
    text: string
    steps: AgentStep[]
    tokens: TokenUsage
    totalCostUsd?: number
    llmDurationMs: number
    iterations: number
    allToolCalls: ToolCall[]
    error?: Error
    timedOut?: boolean
    policyBlocked?: boolean
    policyRetryExceeded?: boolean
  }> {
    const { provider, tools, executeTool, system, maxIterations, timeoutMs, traceId, instructions } = config

    const startMs = performance.now()
    const deadline = startMs + timeoutMs

    const params: CompletionParams = {
      messages: [...initialMessages],
      system,
      tools,
      maxTokens: config.maxTokens ?? DEFAULT_MAX_TOKENS,
    }

    const steps: AgentStep[] = []
    let totalTokens = emptyTokenUsage()
    let totalCostUsd: number | undefined = 0
    let llmDurationMs = 0
    let finalText = ""
    const allToolCalls: ToolCall[] = []

    let response: LLMResponse | undefined
    let iteration = 0
    let loopError: Error | undefined
    let timedOut = false
    let policyBlocked = false
    let policyRetryExceeded = false
    let consecutivePolicyBlocks = 0
    let pendingHistory: Array<{ role: "system" | "user" | "assistant"; content: string }> | undefined
    let lastActionSig = ""
    let repeatCount = 0

    try {
      while (iteration < maxIterations) {
        if (performance.now() > deadline) {
          timedOut = true
          break
        }

        iteration++

        if (!response) {
          response = await provider.complete(params)
          llmDurationMs += response.durationMs
        }

        totalTokens = addTokenUsage(totalTokens, response.tokens)
        if (totalCostUsd !== undefined && response.costUsd !== undefined) {
          totalCostUsd += response.costUsd
        } else {
          totalCostUsd = undefined
        }

        if (config.onAfterLLM) {
          await config.onAfterLLM(response, iteration)
        }

        const toolCalls: ToolCall[] = response.toolCalls.map((tc) => ({
          tool_name: tc.name,
          tool_call_id: tc.id,
          arguments: tc.arguments,
        }))

        steps.push({
          role: "assistant",
          text: response.text || undefined,
          toolCalls,
          timestamp: Date.now(),
        })

        if (response.toolCalls.length === 0 || response.stopReason === "end_turn") {
          finalText = response.text
          break
        }

        const toolResults: LLMToolResult[] = []
        const toolStepCalls: ToolCall[] = []

        for (const tc of response.toolCalls) {
          const toolCall: ToolCall = {
            tool_name: tc.name,
            tool_call_id: tc.id,
            arguments: tc.arguments,
          }

          if (config.onBeforeTool) {
            const beforeResult = await config.onBeforeTool(toolCall, iteration)
            if (beforeResult.action === "block") {
              policyBlocked = true
              consecutivePolicyBlocks++
              const blockReason = beforeResult.reason ?? "Policy violation"
              toolResults.push({
                toolCallId: tc.id,
                content: `⚠️ Tool call blocked: ${blockReason}\n\nPlease try a different approach. If you were trying to access files, use paths within the workspace directory.`,
                isError: true,
              })
              continue
            }
          }

          const result = await executeTool(tc)
          consecutivePolicyBlocks = 0
          toolResults.push({ toolCallId: tc.id, content: result.output })

          const completedCall: ToolCall = {
            tool_name: tc.name,
            tool_call_id: tc.id,
            arguments: tc.arguments,
            result: result.output,
          }
          toolStepCalls.push(completedCall)
          allToolCalls.push(completedCall)

          traceManager.addInstruction(traceId, {
            id: crypto.randomUUID(),
            content: completedCall,
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
          } as Instruction)

          if (config.onAfterTool) {
            await config.onAfterTool(completedCall, iteration)
          }
        }

        steps.push({
          role: "tool",
          toolCalls: toolStepCalls,
          timestamp: Date.now(),
        })

        if (consecutivePolicyBlocks >= (config.maxPolicyRetries ?? 3)) {
          policyRetryExceeded = true
          break
        }

        if (pendingHistory) {
          params.messages.push(...pendingHistory)
        }

        const actionSig = response.toolCalls.map((tc) => `${tc.name}(${JSON.stringify(tc.arguments)})`).sort().join("|")
        pendingHistory = [
          { role: "assistant", content: response.text || `[Called: ${response.toolCalls.map((tc) => tc.name).join(", ")}]` },
          { role: "user", content: toolResults.map((tr) => tr.content.slice(0, 2000)).join("\n---\n") },
        ]

        if (actionSig === lastActionSig) {
          repeatCount++
          if (repeatCount >= 3) {
            finalText = response.text
            break
          }
        } else {
          lastActionSig = actionSig
          repeatCount = 1
        }

        response = await provider.completeWithToolResults(params, toolResults, response)
        llmDurationMs += response.durationMs
      }
    } catch (err) {
      loopError = err instanceof Error ? err : new Error(String(err))
    }

    if (!timedOut && performance.now() > deadline) {
      timedOut = true
    }

    return {
      text: finalText,
      steps,
      tokens: totalTokens,
      totalCostUsd,
      llmDurationMs,
      iterations: iteration,
      allToolCalls,
      error: loopError,
      timedOut,
      policyBlocked,
      policyRetryExceeded,
    }
  }
}
