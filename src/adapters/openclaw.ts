import type { ToolCall, Instruction } from "../types/instruction.ts"
import type { RuntimeHooks } from "../types/hooks.ts"
import { audit } from "../hooks/structured-audit.ts"
import type {
  AdapterConfig as BaseAdapterConfig,
  AgentAdapter,
  AdapterRunConfig,
  AdapterRunResult,
  AgentStep,
  TokenUsage,
  LLMResponse,
  LLMToolCall,
} from "./types.ts"
import {
  OPENCLAW_TOOL_ALIASES,
  parseOpenClawToolCall,
  getOpenClawToolSecurityAttributes,
  type OpenClawToolCall,
  type ParsedToolCall,
} from "./openclaw-tools.ts"
import {
  OpenClawConfigGenerator,
  type OpenClawConfigSnippet,
  type OpenClawFullConfig,
  type OpenClawModelConfig,
} from "./openclaw-config-generator.ts"
import {
  OpenClawSessionManager,
  type OpenClawSession,
  type CreateSessionParams,
} from "./openclaw-session.ts"

export interface OpenClawAdapterConfig extends BaseAdapterConfig {
  proxyUrl?: string
  proxyPort?: number
  optimizeEnabled?: boolean
  optimizeCallback?: (session: OpenClawSession) => Promise<void>
}

export interface OpenClawToolCallResult {
  id: string
  name: string
  args: Record<string, unknown>
  canonicalName: string
  securityAttributes: Partial<import("../types/instruction.ts").SecurityType>
}

export class OpenClawAdapter implements AgentAdapter {
  readonly name = "openclaw"
  readonly experimental = true
  private config: OpenClawAdapterConfig
  private hooks: RuntimeHooks = {}
  private configGenerator: OpenClawConfigGenerator
  private sessionManager: OpenClawSessionManager

  constructor(config: OpenClawAdapterConfig = { model: "" }) {
    this.config = config
    this.configGenerator = new OpenClawConfigGenerator()
    this.sessionManager = new OpenClawSessionManager({
      optimizeEnabled: config.optimizeEnabled ?? false,
      optimizeCallback: config.optimizeCallback,
    })
  }

  async setup(config: BaseAdapterConfig): Promise<void> {
    this.config = { ...this.config, ...config }
  }

  async run(runConfig: AdapterRunConfig): Promise<AdapterRunResult> {
    audit({ severity: "warn", category: "adapter", action: "experimental_run", message: "OpenClawAdapter is experimental and not fully implemented" })

    const sessionId = await this.sessionManager.createSession({
      skillDir: runConfig.workDir,
      taskPrompt: runConfig.prompt,
      workDir: runConfig.workDir,
    })

    this.sessionManager.getSession(sessionId)

    return {
      text: "",
      steps: [],
      tokens: { input: 0, output: 0 },
      cost: 0,
      durationMs: 0,
      llmDurationMs: 0,
      workDir: runConfig.workDir,
      runStatus: "adapter-crashed",
      statusDetail: "OpenClawAdapter is experimental and not fully implemented",
    }
  }

  setHooks(hooks: RuntimeHooks): void {
    this.hooks = hooks
  }

  async teardown(): Promise<void> {
    this.sessionManager.clearCompletedSessions()
  }

  generateProxyConfig(proxyUrl: string, proxyPort?: number): OpenClawConfigSnippet {
    return this.configGenerator.generateConfig({
      proxyUrl,
      proxyPort: proxyPort ?? this.config.proxyPort ?? 4000,
      modelName: this.config.model ?? "default",
    })
  }

  generateFullProxyConfig(params: {
    proxyUrl: string
    proxyPort?: number
    models: Array<{ id: string; name: string }>
    defaultModel?: string
  }): string {
    return this.configGenerator.generateFullConfig({
      proxyUrl: params.proxyUrl,
      proxyPort: params.proxyPort ?? this.config.proxyPort ?? 4000,
      models: params.models,
      defaultModel: params.defaultModel,
    })
  }

  parseToolCalls(toolCalls: OpenClawToolCall[]): OpenClawToolCallResult[] {
    return toolCalls.map((tc) => {
      const parsed = parseOpenClawToolCall(tc)
      const securityAttributes = getOpenClawToolSecurityAttributes(
        parsed.canonicalName,
        parsed.args
      )
      return {
        id: tc.id,
        name: parsed.name,
        args: parsed.args,
        canonicalName: parsed.canonicalName,
        securityAttributes,
      }
    })
  }

  async createSession(params: CreateSessionParams): Promise<string> {
    return this.sessionManager.createSession(params)
  }

  getSession(sessionId: string): OpenClawSession | null {
    return this.sessionManager.getSession(sessionId)
  }

  getSessionByTraceId(traceId: string): OpenClawSession | null {
    return this.sessionManager.getSessionByTraceId(traceId)
  }

  async endSession(sessionId: string): Promise<void> {
    await this.sessionManager.endSession(sessionId)
  }

  recordToolCalls(sessionId: string, toolCalls: OpenClawToolCall[]): ParsedToolCall[] {
    return this.sessionManager.recordToolCalls(sessionId, toolCalls)
  }

  recordToolResult(sessionId: string, toolCallId: string, result: string): void {
    this.sessionManager.recordToolResult(sessionId, toolCallId, result)
  }

  async triggerOptimize(skillDir: string, traceId: string): Promise<void> {
    const session = this.sessionManager.getSessionByTraceId(traceId)
    if (session) {
      await this.sessionManager.triggerOptimize(session.id)
    }
  }

  setOptimizeEnabled(enabled: boolean): void {
    this.sessionManager.setOptimizeEnabled(enabled)
  }

  setOptimizeCallback(callback: (session: OpenClawSession) => Promise<void>): void {
    this.sessionManager.setOptimizeCallback(callback)
  }

  getToolAliases(): Record<string, string> {
    return { ...OPENCLAW_TOOL_ALIASES }
  }

  getSecurityAttributes(
    toolName: string,
    args: Record<string, unknown>
  ): Partial<import("../types/instruction.ts").SecurityType> {
    return getOpenClawToolSecurityAttributes(toolName, args)
  }

  getActiveSessions(): OpenClawSession[] {
    return this.sessionManager.getActiveSessions()
  }

  clearCompletedSessions(): number {
    return this.sessionManager.clearCompletedSessions()
  }

  generateEnvVars(proxyUrl: string, proxyPort?: number): Record<string, string> {
    return this.configGenerator.generateEnvVars({
      proxyUrl,
      proxyPort: proxyPort ?? this.config.proxyPort ?? 4000,
    })
  }
}

export {
  OPENCLAW_TOOL_ALIASES,
  parseOpenClawToolCall,
  getOpenClawToolSecurityAttributes,
  OpenClawConfigGenerator,
  OpenClawSessionManager,
}

export type {
  OpenClawToolCall,
  ParsedToolCall,
} from "./openclaw-tools.ts"

export type {
  OpenClawConfigSnippet,
  OpenClawFullConfig,
  OpenClawModelConfig,
} from "./openclaw-config-generator.ts"

export type {
  OpenClawSession,
  CreateSessionParams,
  SessionOptimizeResult,
} from "./openclaw-session.ts"
