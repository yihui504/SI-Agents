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
import type { ToolCall, Instruction } from "../types/instruction.ts"
import { createSecurityCheckHook, type SecurityCheckHookConfig } from "./security-check.ts"
import { createTaintTrackHook, type TaintTrackHookConfig } from "./taint-track.ts"
import { createAuditLogHook, type AuditLogHookConfig } from "./audit-log.ts"
import { checkResponsePolicy } from "../policy/check.ts"

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
}

export class HookCoordinator {
  private config: HookCoordinatorConfig
  private hooks: RuntimeHooks
  private instructions: Instruction[] = []

  constructor(config: HookCoordinatorConfig) {
    this.config = config
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

    if (this.config.boostCandidates && this.config.boostCandidates.length > 0) {
      this.monitorBoostCandidates(ctx)
    }
  }

  async beforeTool(ctx: BeforeToolContext): Promise<BeforeToolResult> {
    if (this.hooks.beforeTool) {
      for (const hook of this.hooks.beforeTool) {
        const result = await hook(ctx)
        if (result.action === "block") {
          return result
        }
      }
    }

    return { action: "passthrough" }
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

  private createBeforeToolHook(): (ctx: BeforeToolContext) => Promise<BeforeToolResult> {
    return async (ctx: BeforeToolContext): Promise<BeforeToolResult> => {
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
            return {
              action: "block",
              reason: `Taint policy violation: ${taintCheck.reason}`,
            }
          }
        }
      }

      let checkInstruction = instruction
      if (!checkInstruction) {
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
          instruction_type: "EXEC",
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
          return {
            action: "block",
            reason: `Taint policy violation: ${taintCheck.reason}`,
          }
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
      for (const policy of policies) {
        const result = await policy.check(
          this.instructions.map(i => i as unknown as Record<string, unknown>),
          { tool_calls: [openaiFormatToolCall] },
          [checkInstruction],
          this.config.traceId,
        )

        if (result.error_type) {
          return {
            action: "block",
            reason: `Policy violation: ${result.error_type}`,
          }
        }
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
