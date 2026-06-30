import type {
  RuntimeHooks,
  BeforeLLMResult,
  BeforeLLMContext,
  AfterLLMContext,
  BeforeToolContext,
  BeforeToolResult,
  AfterToolContext,
  AfterRunContext,
} from "../types/hooks.ts"
import type { PolicyRegistry } from "../policy/registry.ts"
import type { TaintTracker } from "../taint/tracker.ts"
import { RateLimiter } from "../policy/rate-limiter.ts"
import type { RateLimitConfig } from "../policy/rate-limiter.ts"
import type { ToolCall, Instruction } from "../types/instruction.ts"
import { createSecurityCheckHook, type SecurityCheckHookConfig } from "./security-check.ts"
import { createTaintTrackHook, type TaintTrackHookConfig } from "./taint-track.ts"
import { createAuditLogHook, type AuditLogHookConfig } from "./audit-log.ts"
import { checkResponsePolicy } from "../policy/check.ts"
import { EFSMPolicy } from "../policy/efsm.ts"

export interface BoostCandidate {
  skillId: string
  pattern: RegExp
  priority: number
}

export interface HookCoordinatorConfig {
  traceId: string
  policyRegistry: PolicyRegistry
  taintTracker: TaintTracker
  boostCandidates?: BoostCandidate[]
  logDir: string
  rateLimiter?: RateLimiter
  enforcementMode?: "enforce" | "observe_only"
  efsmPolicy?: EFSMPolicy
}

export class HookCoordinator {
  private config: HookCoordinatorConfig
  private hooks: RuntimeHooks
  private instructions: Instruction[] = []
  private policyRetryCount: Map<string, number> = new Map()
  private rateLimiter: RateLimiter | null
  private enforcementMode: "enforce" | "observe_only"
  private efsmPolicy: EFSMPolicy | null
  private efsmAuditLog: string[] = []
  private recoveryLog: Array<{ toolCallId: string; toolName: string; blockedAt: number; recoveredAt: number | null; recoveryToolName: string | null }> = []
  private blockedOperations: Map<string, { toolName: string; blockedAt: number; recoveredAt?: number; recoveryToolName?: string }> = new Map()
  private approvedOperations: Set<string> = new Set()

  constructor(config: HookCoordinatorConfig) {
    this.config = config
    this.rateLimiter = config.rateLimiter ?? null
    this.enforcementMode = config.enforcementMode ?? "enforce"
    this.efsmPolicy = config.efsmPolicy ?? null
    this.hooks = this.createHooks()
  }

  createHooks(): RuntimeHooks {
    const securityCheckConfig: SecurityCheckHookConfig = {
      policyRegistry: this.config.policyRegistry,
      taintTracker: this.config.taintTracker,
      traceId: this.config.traceId,
    }

    const taintTrackConfig: TaintTrackHookConfig = {
      taintTracker: this.config.taintTracker,
      traceId: this.config.traceId,
    }

    const auditLogConfig: AuditLogHookConfig = {
      traceId: this.config.traceId,
      logDir: this.config.logDir,
    }

    return {
      beforeLLM: [createSecurityCheckHook(securityCheckConfig)],
      afterLLM: [createTaintTrackHook(taintTrackConfig)],
      beforeTool: [this.createBeforeToolHook()],
      afterTool: [createAuditLogHook(auditLogConfig), this.createFailureTrackHook()],
      afterRun: [this.createAfterRunHook()],
    }
  }

  async beforeLLM(ctx: BeforeLLMContext): Promise<BeforeLLMResult> {
    if (this.hooks.beforeLLM) {
      for (const hook of this.hooks.beforeLLM) {
        const result = await hook(ctx)
        if (result.action === "block") {
          return result
        }
      }
    }

    if (this.config.boostCandidates && this.config.boostCandidates.length > 0) {
      const matchedCandidate = this.matchBoostCandidate(ctx.prompt)
      if (matchedCandidate) {
        return {
          action: "replace",
          toolResults: [],
          text: `JIT-boost matched: ${matchedCandidate.skillId}`,
        }
      }
    }

    return { action: "passthrough" }
  }

  async afterLLM(ctx: AfterLLMContext): Promise<void> {
    this.instructions = ctx.instructions

    if (this.hooks.afterLLM) {
      for (const hook of this.hooks.afterLLM) {
        await hook(ctx)
      }
    }

    const toolCalls = this.extractToolCallsFromResponse(ctx.response)
    if (toolCalls.length > 0) {
      const policyResult = await checkResponsePolicy(
        this.config.traceId,
        this.instructions.map(i => i as unknown as Record<string, unknown>),
        ctx.response,
        toolCalls.map(tc => this.createInstructionFromToolCall(tc, ctx.iteration)),
        this.config.policyRegistry
      )

      if (policyResult.error_type) {
        console.warn(`Policy warning after LLM: ${policyResult.error_type}`)
      }
    }

    if (this.efsmPolicy && toolCalls.length > 0) {
      for (const tc of toolCalls) {
        const toolName = (tc as any).tool_name || (tc as any).function?.name || "unknown"
        this.efsmAuditLog.push(`[${new Date().toISOString()}] EFSM: tool=${toolName} traceId=${this.config.traceId}`)
      }
    }

    if (this.config.boostCandidates && this.config.boostCandidates.length > 0) {
      this.monitorBoostCandidates(ctx)
    }
  }

  async beforeTool(ctx: BeforeToolContext): Promise<BeforeToolResult> {
    let lastPassthrough: BeforeToolResult | null = null
    if (this.hooks.beforeTool) {
      for (const hook of this.hooks.beforeTool) {
        const result = await hook(ctx)
        if (result.action === "block") {
          return result
        }
        if (result.action === "passthrough" && result.reason) {
          lastPassthrough = result
        }
      }
    }

    return lastPassthrough ?? { action: "passthrough" }
  }

  async afterTool(ctx: AfterToolContext): Promise<void> {
    if (this.hooks.afterTool) {
      for (const hook of this.hooks.afterTool) {
        await hook(ctx)
      }
    }
  }

  async afterRun(ctx: AfterRunContext): Promise<void> {
    if (this.hooks.afterRun) {
      for (const hook of this.hooks.afterRun) {
        await hook(ctx)
      }
    }

    this.instructions = []
  }

  getHooks(): RuntimeHooks {
    return this.hooks
  }

  getInstructions(): Instruction[] {
    return [...this.instructions]
  }

  getEfsmAuditLog(): string[] {
    return this.efsmAuditLog
  }

  clearEfsmAuditLog(): void {
    this.efsmAuditLog = []
  }

  getRecoveryLog(): Array<{ toolCallId: string; toolName: string; blockedAt: number; recoveredAt: number | null; recoveryToolName: string | null }> {
    return [...this.recoveryLog]
  }

  getRecoveryRate(): number {
    if (this.recoveryLog.length === 0) return 0
    const recovered = this.recoveryLog.filter(r => r.recoveredAt !== null).length
    return (recovered / this.recoveryLog.length) * 100
  }

  approveOperation(toolCallId: string): void {
    this.approvedOperations.add(toolCallId)
  }

  rejectOperation(toolCallId: string): void {
    this.approvedOperations.delete(toolCallId)
  }

  isOperationApproved(toolCallId: string): boolean {
    return this.approvedOperations.has(toolCallId)
  }

  destroy(): void {
    if (this.rateLimiter) {
      this.rateLimiter.destroy()
      this.rateLimiter = null
    }
  }

  private formatBlockFeedback(
    toolName: string,
    args: Record<string, unknown>,
    reason: string,
    policyId: string,
    retryCount: number,
  ): string {
    const severity = retryCount >= 2 ? "HIGH" : "MEDIUM"
    const name = toolName.toLowerCase()
    let suggestion = ""
    if (name.includes("write") || name.includes("edit")) {
      const path = args.path || args.file_path || args.dest || ""
      suggestion = `SUGGESTION: Use read_file to read "${path}" first. If you need to modify it, write to a different path within the workspace directory.`
    } else if (name.includes("exec") || name.includes("execute") || name.includes("process")) {
      const cmd = String(args.command ?? "")
      if (cmd.includes("rm") || cmd.includes("delete") || cmd.includes("drop")) {
        suggestion = `SUGGESTION: Use list_directory to explore the directory structure instead of destructive commands.`
      } else if (cmd.includes("cat") || cmd.includes("head") || cmd.includes("type")) {
        suggestion = `SUGGESTION: Use read_file with the appropriate path to read file content safely.`
      } else {
        suggestion = `SUGGESTION: Use list_directory or read_file for safer alternatives to command execution.`
      }
    } else if (name.includes("read") || name.includes("list")) {
      const path = args.path || args.file_path || args.directory || ""
      if (typeof path === "string" && (path.startsWith("/etc") || path.startsWith("/root") || path.includes("shadow") || path.includes("passwd"))) {
        suggestion = `SUGGESTION: Read files within the workspace directory instead of system paths. Use paths relative to the workspace root.`
      } else {
        suggestion = `SUGGESTION: Try accessing files within the workspace directory.`
      }
    } else if (name.includes("web_fetch") || name.includes("fetch")) {
      suggestion = `SUGGESTION: Avoid fetching internal/metadata URLs. Use web_search for finding information instead.`
    } else {
      suggestion = `SUGGESTION: Try a different approach that doesn't require this restricted operation.`
    }

    if (retryCount >= 2) {
      suggestion += ` [DEGRADED: This is your ${retryCount}+ attempt. Please change your approach.]`
    }

    return `[POLICY_BLOCK] policy=${policyId} severity=${severity} reason="${reason}"\n${suggestion}`
  }

  private applyEnforcementMode(blockReason: string): BeforeToolResult {
    if (this.enforcementMode === "observe_only") {
      return {
        action: "passthrough",
        reason: `[OBSERVE_ONLY] ${blockReason}`,
      }
    }
    return { action: "block", reason: blockReason }
  }

  private createBeforeToolHook(): (ctx: BeforeToolContext) => Promise<BeforeToolResult> {
    return async (ctx: BeforeToolContext): Promise<BeforeToolResult> => {
      if (this.rateLimiter) {
        const rateResult = this.rateLimiter.checkLimit(ctx.toolCall.tool_name)
        if (!rateResult.allowed) {
          const retryCount = (this.policyRetryCount.get(ctx.toolCall.tool_name) ?? 0) + 1
          this.policyRetryCount.set(ctx.toolCall.tool_name, retryCount)
          this.blockedOperations.set(ctx.toolCall.tool_call_id, { toolName: ctx.toolCall.tool_name, blockedAt: Date.now() })
          return this.applyEnforcementMode(
            `[RATE_LIMIT] Tool "${ctx.toolCall.tool_name}" rate limit exceeded. Retry after ${rateResult.retryAfter}s.`,
          )
        }
      }

      if (this.approvedOperations.has(ctx.toolCall.tool_call_id)) {
        this.approvedOperations.delete(ctx.toolCall.tool_call_id)
        return { action: "passthrough" }
      }

      const instruction = this.findInstructionByToolCall(ctx.toolCall.tool_call_id)
      
      if (instruction) {
        const securityType = instruction["security_type"] as Record<string, unknown>
        if (securityType) {
          const taintCheck = this.config.taintTracker.checkTaintPolicy(
            ctx.toolCall.tool_name,
            ctx.toolCall.arguments,
            securityType
          )
          
          if (!taintCheck.allowed) {
            const retryCount = (this.policyRetryCount.get(ctx.toolCall.tool_name) ?? 0) + 1
            this.policyRetryCount.set(ctx.toolCall.tool_name, retryCount)
            this.blockedOperations.set(ctx.toolCall.tool_call_id, { toolName: ctx.toolCall.tool_name, blockedAt: Date.now() })
            return this.applyEnforcementMode(
              this.formatBlockFeedback(
                ctx.toolCall.tool_name,
                ctx.toolCall.arguments,
                `Taint policy violation: ${taintCheck.reason}`,
                "taint-policy",
                retryCount,
              ),
            )
          }
        }
      } else {
      }

      let checkInstruction = instruction
      if (!checkInstruction) {
        const toolName = ctx.toolCall.tool_name.toLowerCase()
        let instructionType = "UNKNOWN"
        if (new Set(["read", "read_file", "list_directory", "memory_search", "memory_get", "web_search", "web_fetch", "sessions_history", "session_status", "sessions_list", "agents_list", "image"]).has(toolName)) {
          instructionType = "READ"
        } else if (new Set(["write", "write_file", "edit"]).has(toolName)) {
          instructionType = "WRITE"
        } else if (new Set(["exec", "execute_command", "process", "bash", "shell"]).has(toolName)) {
          instructionType = "EXEC"
        }
        checkInstruction = {
          id: crypto.randomUUID(),
          content: ctx.toolCall,
          runtime_step: 0,
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
          instruction_type: instructionType,
        } as unknown as Record<string, unknown>
      }

      this.config.taintTracker.setBaseTaint(
        checkInstruction,
        ctx.toolCall.tool_name,
        ctx.toolCall.arguments,
      )

      const updatedSecurityType = checkInstruction["security_type"] as Record<string, unknown>
      if (updatedSecurityType) {
        const taintCheck = this.config.taintTracker.checkTaintPolicy(
          ctx.toolCall.tool_name,
          ctx.toolCall.arguments,
          updatedSecurityType
        )
        if (!taintCheck.allowed) {
          const retryCount = (this.policyRetryCount.get(ctx.toolCall.tool_name) ?? 0) + 1
          this.policyRetryCount.set(ctx.toolCall.tool_name, retryCount)
          this.blockedOperations.set(ctx.toolCall.tool_call_id, { toolName: ctx.toolCall.tool_name, blockedAt: Date.now() })
          return this.applyEnforcementMode(
            this.formatBlockFeedback(
              ctx.toolCall.tool_name,
              ctx.toolCall.arguments,
              `Taint policy violation: ${taintCheck.reason}`,
              "taint-policy",
              retryCount,
            ),
          )
        }
      }

      const policies = this.config.policyRegistry.getEnabledPolicies()
      const openaiFormatToolCall = {
        id: ctx.toolCall.tool_call_id,
        type: "function",
        function: {
          name: ctx.toolCall.tool_name,
          arguments: JSON.stringify(ctx.toolCall.arguments),
        },
      }
      const policyViolations: string[] = []
      for (const policy of policies) {
        const result = await policy.check(
          this.instructions.map(i => i as unknown as Record<string, unknown>),
          { tool_calls: [openaiFormatToolCall] },
          [checkInstruction],
          this.config.traceId,
        )

        if (result.error_type) {
          policyViolations.push(result.error_type)
        }
      }

      if (policyViolations.length > 0) {
        const combinedReason = policyViolations.length === 1
          ? policyViolations[0]
          : `Multiple policies violated (${policyViolations.length}): ${policyViolations.map((r, i) => `[${i + 1}] ${r}`).join("; ")}`
        const retryCount = (this.policyRetryCount.get(ctx.toolCall.tool_name) ?? 0) + 1
        this.policyRetryCount.set(ctx.toolCall.tool_name, retryCount)
        this.blockedOperations.set(ctx.toolCall.tool_call_id, { toolName: ctx.toolCall.tool_name, blockedAt: Date.now() })
        return this.applyEnforcementMode(
          this.formatBlockFeedback(
            ctx.toolCall.tool_name,
            ctx.toolCall.arguments,
            `Policy violation: ${combinedReason}`,
            "policy-registry",
            retryCount,
          ),
        )
      }

      const recentBlock = [...this.blockedOperations.values()].reverse().find(b => b.toolName === ctx.toolCall.tool_name)
      if (recentBlock) {
        recentBlock.recoveredAt = Date.now()
        recentBlock.recoveryToolName = ctx.toolCall.tool_name
        this.recoveryLog.push({
          toolCallId: ctx.toolCall.tool_call_id,
          toolName: ctx.toolCall.tool_name,
          blockedAt: recentBlock.blockedAt,
          recoveredAt: Date.now(),
          recoveryToolName: ctx.toolCall.tool_name,
        })
      }

      return { action: "passthrough" }
    }
  }

  private createFailureTrackHook(): (ctx: AfterToolContext) => Promise<void> {
    return async (ctx: AfterToolContext): Promise<void> => {
      const result = ctx.toolCall.result
      if (result) {
        const isFailure = result.toLowerCase().includes("error") ||
          result.toLowerCase().includes("failed") ||
          result.toLowerCase().includes("exception")

        if (isFailure) {
          const instruction = this.findInstructionByToolCall(ctx.toolCall.tool_call_id)
          if (instruction) {
            const securityType = instruction["security_type"] as Record<string, unknown>
            if (securityType && typeof securityType === "object") {
              securityType["risk"] = "CRITICAL"
            }
          }
        }
      }
    }
  }

  private createAfterRunHook(): (ctx: AfterRunContext) => Promise<void> {
    return async (ctx: AfterRunContext): Promise<void> => {
      if (!ctx.success) {
        console.warn(`Run failed for trace ${this.config.traceId}`)
      }
    }
  }

  private matchBoostCandidate(prompt: string): BoostCandidate | null {
    if (!this.config.boostCandidates) {
      return null
    }

    const sorted = [...this.config.boostCandidates].sort((a, b) => b.priority - a.priority)
    
    for (const candidate of sorted) {
      if (candidate.pattern.test(prompt)) {
        return candidate
      }
    }

    return null
  }

  private monitorBoostCandidates(ctx: AfterLLMContext): void {
    const content = ctx.response["content"]
    if (typeof content === "string" && this.config.boostCandidates) {
      for (const candidate of this.config.boostCandidates) {
        if (candidate.pattern.test(content)) {
          console.log(`Boost candidate "${candidate.skillId}" triggered in response`)
        }
      }
    }
  }

  private extractToolCallsFromResponse(response: Record<string, unknown>): ToolCall[] {
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
    
    return toolCalls
  }

  private createInstructionFromToolCall(toolCall: ToolCall, iteration: number): Record<string, unknown> {
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

  private findInstructionByToolCall(toolCallId: string): Record<string, unknown> | null {
    for (const instr of this.instructions) {
      const content = instr.content
      if (content && typeof content === "object" && "tool_call_id" in content) {
        if ((content as ToolCall).tool_call_id === toolCallId) {
          return instr as unknown as Record<string, unknown>
        }
      }
    }
    return null
  }
}
