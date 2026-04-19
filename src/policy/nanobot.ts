import { Policy } from "./policy.ts"
import type { PolicyCheckResult } from "../types/policy.ts"

export interface NanobotPolicyConfig {
  enabled: boolean
  execDenyPatterns: string[]
}

export class NanobotPolicy extends Policy {
  readonly name = "nanobot"
  private config: NanobotPolicyConfig

  constructor(config: NanobotPolicyConfig = { enabled: true, execDenyPatterns: [] }) {
    super()
    this.config = config
  }

  async check(
    instructions: Record<string, unknown>[],
    currentResponse: Record<string, unknown>,
    latestInstructions: Record<string, unknown>,
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
      for (const pattern of this.config.execDenyPatterns) {
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

  /**
   * Check a command against deny patterns (utility method)
   * Returns true if the command is allowed, false if blocked
   */
  checkCommand(command: string): { allowed: boolean; message?: string } {
    if (!this.config.enabled) {
      return { allowed: true }
    }

    for (const pattern of this.config.execDenyPatterns) {
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
