import { Policy } from "./policy.ts"
import type { PolicyCheckResult } from "../types/policy.ts"
import { audit } from "../hooks/structured-audit.ts"

const REDOS_RISK_PATTERNS = [
  /(\+|\*){2,}/,
  /\([^)]*\+[^)]*\)[\+\*]/,
  /\(\?\:/,
  /\{.*\d{3,}.*\}/,
]

function validateDenyPattern(pattern: string): { safe: boolean; reason: string | null } {
  for (const riskPattern of REDOS_RISK_PATTERNS) {
    if (riskPattern.test(pattern)) {
      return { safe: false, reason: `Pattern "${pattern}" contains potentially dangerous regex constructs` }
    }
  }
  if (pattern.length > 200) {
    return { safe: false, reason: `Pattern too long (${pattern.length} chars, max 200)` }
  }
  return { safe: true, reason: null }
}



export interface NanobotPolicyConfig {
  enabled: boolean
  execDenyPatterns: string[]
}

export class NanobotPolicy extends Policy {
  readonly name = "nanobot"
  private config: NanobotPolicyConfig
  private safeDenyPatterns: string[]

  constructor(config: NanobotPolicyConfig = { enabled: true, execDenyPatterns: [] }) {
    super()
    this.config = { enabled: config.enabled ?? true, execDenyPatterns: config.execDenyPatterns ?? [] }
    this.safeDenyPatterns = []
    for (const pattern of this.config.execDenyPatterns) {
      const { safe, reason } = validateDenyPattern(pattern)
      if (!safe) {
        audit({ severity: "warn", category: "policy", action: "pattern_validation", message: `Skipping unsafe deny pattern: ${reason}`, policyName: "NanobotPolicy" })
        continue
      }
      this.safeDenyPatterns.push(pattern)
    }
  }

  async check(
    instructions: Record<string, unknown>[],
    currentResponse: Record<string, unknown>,
    latestInstructions: Record<string, unknown>[],
    traceId: string,
  ): Promise<PolicyCheckResult> {
    if (!this.config.enabled) {
      return {
        modified: false,
        response: currentResponse,
        error_type: null,
        inactivate_error_type: null,
        policy_names: [],
        policy_sources: {},
      }
    }

    const toolCalls = currentResponse.tool_calls as Array<Record<string, unknown>> | undefined
    if (!toolCalls) {
      return {
        modified: false,
        response: currentResponse,
        error_type: null,
        inactivate_error_type: null,
        policy_names: [],
        policy_sources: {},
      }
    }

    const response = { ...currentResponse }
    const kept: Record<string, unknown>[] = []
    const errors: string[] = []

    for (const tc of toolCalls) {
      const func = tc.function as { name: string; arguments: string } | undefined
      if (!func) {
        kept.push(tc)
        continue
      }

      const toolName = func.name.toLowerCase()
      if (!["exec", "execute_command", "process", "terminal", "bash", "shell"].includes(toolName)) {
        kept.push(tc)
        continue
      }

      let args: Record<string, unknown> = {}
      try {
        args = JSON.parse(func.arguments)
      } catch {
        kept.push(tc)
        continue
      }

      const command = String(args.command || args.cmd || args.script || "")
      let blocked = false
      for (const pattern of this.safeDenyPatterns) {
        if (command.includes(pattern) || new RegExp(pattern, "i").test(command)) {
          errors.push(`命令包含被禁止的模式: ${pattern}`)
          blocked = true
          break
        }
      }
      if (!blocked) {
        kept.push(tc)
      }
    }

    if (errors.length > 0) {
      response.tool_calls = kept.length > 0 ? kept : null
      if (kept.length === 0) {
        response.function_call = null
        if (typeof response.content !== "string" || !response.content) {
          response.content = errors.join("\n\n")
        }
      }
      return {
        modified: true,
        response,
        error_type: errors.join("\n\n"),
        inactivate_error_type: null,
        policy_names: [this.name],
        policy_sources: {},
      }
    }

    return {
      modified: false,
      response: currentResponse,
      error_type: null,
      inactivate_error_type: null,
      policy_names: [],
      policy_sources: {},
    }
  }

  checkCommand(command: string): { allowed: boolean; message?: string } {
    if (!this.config.enabled) {
      return { allowed: true }
    }

    for (const pattern of this.safeDenyPatterns) {
      if (command.includes(pattern) || new RegExp(pattern, "i").test(command)) {
        return {
          allowed: false,
          message: `命令包含被禁止的模式: ${pattern}`,
        }
      }
    }

    return { allowed: true }
  }
}
