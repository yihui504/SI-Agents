import { spawn } from "node:child_process"
import type { PolicyRegistry } from "../policy/registry.ts"
import type { TaintTracker } from "../taint/tracker.ts"
import type { RuntimeHooks, BeforeLLMContext, BeforeLLMResult, AfterLLMContext } from "../types/hooks.ts"
import type { ToolCall } from "../types/instruction.ts"
import type {
  BoostCandidate,
  SolidificationState,
  BoostStats,
  ParamDef,
  ExtractionResult,
} from "./types.ts"
import { normalizeParamDef } from "./types.ts"
import { BoostSecurityAuditor } from "./security-audit.ts"

const DEFAULT_PROMOTION_THRESHOLD = 3
const DEFAULT_DEMOTION_THRESHOLD = 3
const DEFAULT_MONITORED_TOOLS = new Set(["exec", "execute_command", "write", "write_file", "web_fetch", "list_directory", "read", "read_file"])

export interface SolidifierConfig {
  skillId: string
  policyRegistry: PolicyRegistry
  taintTracker: TaintTracker
  promotionThreshold?: number
  demotionThreshold?: number
  monitoredTools?: Set<string>
}

export class Solidifier {
  private candidates: BoostCandidate[]
  private state: Map<string, SolidificationState>
  private auditor: BoostSecurityAuditor
  private promotionThreshold: number
  private demotionThreshold: number
  private monitoredTools: Set<string>
  private skillId: string

  constructor(config: SolidifierConfig, candidates: BoostCandidate[], savedState?: Map<string, SolidificationState>) {
    this.skillId = config.skillId
    this.candidates = candidates
    this.promotionThreshold = config.promotionThreshold ?? DEFAULT_PROMOTION_THRESHOLD
    this.demotionThreshold = config.demotionThreshold ?? DEFAULT_DEMOTION_THRESHOLD
    this.monitoredTools = config.monitoredTools ?? DEFAULT_MONITORED_TOOLS
    this.auditor = new BoostSecurityAuditor(config.policyRegistry, config.taintTracker)

    if (savedState) {
      this.state = new Map(savedState)
    } else {
      this.state = new Map()
      for (const c of candidates) {
        this.state.set(c.id, {
          candidateId: c.id,
          matchCount: 0,
          fallbackCount: 0,
          promoted: false,
          lastMatch: 0,
        })
      }
    }
  }

  createBeforeLLMHook(): (ctx: BeforeLLMContext) => Promise<BeforeLLMResult> {
    return async (ctx: BeforeLLMContext): Promise<BeforeLLMResult> => {
      for (const candidate of this.candidates) {
        const state = this.state.get(candidate.id)
        if (!state || !state.promoted) continue

        const matchedCandidate = this.matchCandidate(ctx.prompt)
        if (!matchedCandidate || matchedCandidate.id !== candidate.id) continue

        const extraction = await this.extractParamsFromPrompt(ctx.prompt, candidate)
        if (!extraction.complete) {
          continue
        }

        const code = this.instantiateTemplate(candidate.functionTemplate, extraction.params)
        if (/\$\{[^}]+\}/.test(code)) {
          continue
        }

        const auditResult = await this.auditor.auditBeforeExecution(candidate, extraction.params)
        if (!auditResult.passed) {
          state.fallbackCount++
          if (state.fallbackCount >= this.demotionThreshold) {
            this.demote(candidate)
          }
          continue
        }

        try {
          const result = await this.executeTemplate(code, candidate.materializationType ?? "shell", ctx.workDir)

          const afterAudit = await this.auditor.auditAfterExecution(candidate, result.output)
          if (!afterAudit.passed) {
            state.fallbackCount++
            if (state.fallbackCount >= this.demotionThreshold) {
              this.demote(candidate)
            }
            continue
          }

          if (result.success) {
            const toolCall: ToolCall = {
              tool_name: "exec",
              tool_call_id: `boost-${candidate.id}-${Date.now()}`,
              arguments: { command: code },
              result: result.output,
            }
            return {
              action: "replace",
              toolResults: [toolCall],
              text: result.output,
            }
          } else {
            state.fallbackCount++
            if (state.fallbackCount >= this.demotionThreshold) {
              this.demote(candidate)
            }
          }
        } catch {
          state.fallbackCount++
          if (state.fallbackCount >= this.demotionThreshold) {
            this.demote(candidate)
          }
        }
      }

      return { action: "passthrough" }
    }
  }

  createAfterLLMHook(): (ctx: AfterLLMContext) => Promise<void> {
    return async (ctx: AfterLLMContext): Promise<void> => {
      const response = ctx.response as Record<string, unknown>
      const toolCalls = this.extractToolCalls(response)

      for (const tc of toolCalls) {
        const content = this.extractMonitorableContent(tc)
        if (!content) continue

        for (const candidate of this.candidates) {
          const state = this.state.get(candidate.id)
          if (!state || state.promoted) continue

          const candidateTools = candidate.monitoredTools
            ? new Set(candidate.monitoredTools)
            : this.monitoredTools

          const toolName = tc.tool_name.toLowerCase()
          if (!candidateTools.has(toolName) && !candidateTools.has(tc.tool_name)) continue

          try {
            const regex = new RegExp(candidate.codeSignature, "i")
            if (regex.test(content)) {
              state.matchCount++
              state.lastMatch = Date.now()

              if (state.matchCount >= this.promotionThreshold) {
                this.promote(candidate)
              }
            }
          } catch {
          }
        }
      }
    }
  }

  private matchCandidate(prompt: string): BoostCandidate | null {
    const promptLower = prompt.toLowerCase()

    for (const candidate of this.candidates) {
      const state = this.state.get(candidate.id)
      if (!state || !state.promoted) continue

      const keywordMatch = candidate.keywords.some((kw) =>
        promptLower.includes(kw.toLowerCase())
      )
      if (keywordMatch) {
        return candidate
      }
    }

    return null
  }

  private async executeTemplate(
    code: string,
    type: "shell" | "python",
    workDir: string,
  ): Promise<{ success: boolean; output: string; durationMs: number }> {
    const start = performance.now()

    return new Promise((resolve) => {
      let proc: ReturnType<typeof spawn>

      if (type === "shell") {
        proc = spawn("sh", ["-c", code], { cwd: workDir })
      } else {
        proc = spawn("python3", ["-c", code], { cwd: workDir })
      }

      let stdout = ""
      let stderr = ""

      proc.stdout?.on("data", (data) => {
        stdout += data.toString()
      })

      proc.stderr?.on("data", (data) => {
        stderr += data.toString()
      })

      proc.on("close", (code) => {
        const durationMs = performance.now() - start
        resolve({
          success: code === 0,
          output: stdout + (stderr ? `\nstderr: ${stderr}` : ""),
          durationMs,
        })
      })

      proc.on("error", (err) => {
        const durationMs = performance.now() - start
        resolve({
          success: false,
          output: `Error: ${err.message}`,
          durationMs,
        })
      })
    })
  }

  private promote(candidate: BoostCandidate): void {
    const state = this.state.get(candidate.id)
    if (state) {
      state.promoted = true
    }
  }

  private demote(candidate: BoostCandidate): void {
    const state = this.state.get(candidate.id)
    if (state) {
      state.promoted = false
      state.matchCount = 0
    }
  }

  exportState(): Map<string, SolidificationState> {
    return new Map(this.state)
  }

  getStats(): BoostStats {
    let promotedCount = 0
    let totalMatches = 0
    let totalFallbacks = 0

    const candidateStats = this.candidates.map((c) => {
      const state = this.state.get(c.id)
      if (state?.promoted) promotedCount++
      totalMatches += state?.matchCount ?? 0
      totalFallbacks += state?.fallbackCount ?? 0

      return {
        id: c.id,
        promoted: state?.promoted ?? false,
        matchCount: state?.matchCount ?? 0,
        fallbackCount: state?.fallbackCount ?? 0,
      }
    })

    return {
      totalCandidates: this.candidates.length,
      promotedCount,
      totalMatches,
      totalFallbacks,
      candidates: candidateStats,
    }
  }

  private async extractParamsFromPrompt(prompt: string, candidate: BoostCandidate): Promise<ExtractionResult> {
    const paramEntries = Object.entries(candidate.params)
    if (paramEntries.length === 0) {
      return { params: {}, complete: true, method: "regex" }
    }

    const defs: Record<string, ParamDef> = {}
    for (const [name, value] of paramEntries) {
      defs[name] = normalizeParamDef(name, value)
    }

    const regexParams = this.extractViaRegex(prompt, defs)
    if (Object.keys(regexParams).length === paramEntries.length) {
      return { params: regexParams, complete: true, method: "regex" }
    }

    return { params: regexParams, complete: false, method: "none" }
  }

  private extractViaRegex(prompt: string, defs: Record<string, ParamDef>): Record<string, string> {
    const params: Record<string, string> = {}

    for (const [name, def] of Object.entries(defs)) {
      if (!def.extractPattern) continue
      try {
        const match = prompt.match(new RegExp(def.extractPattern, "i"))
        if (match?.[1]) {
          params[name] = match[1].trim()
        }
      } catch {
        // Invalid regex, skip
      }
    }

    return params
  }

  private instantiateTemplate(template: string, params: Record<string, string>): string {
    let result = template
    for (const [key, value] of Object.entries(params)) {
      result = result.replaceAll(`\${${key}}`, value)
    }
    return result
  }

  private extractToolCalls(response: Record<string, unknown>): ToolCall[] {
    const tcs = response.tool_calls
    if (Array.isArray(tcs)) {
      return tcs.filter((tc): tc is ToolCall =>
        tc !== null && typeof tc === "object" && "tool_name" in tc
      )
    }
    const tcs2 = response.toolCalls
    if (Array.isArray(tcs2)) {
      return tcs2.filter((tc): tc is Record<string, unknown> =>
        tc !== null && typeof tc === "object" && "name" in tc
      ).map((tc) => ({
        tool_name: tc.name as string,
        tool_call_id: tc.id as string,
        arguments: tc.arguments as Record<string, unknown>,
      }))
    }
    return []
  }

  private extractMonitorableContent(tc: ToolCall): string {
    const name = tc.tool_name.toLowerCase()
    if (name === "exec" || name === "execute_command") {
      return (tc.arguments.command as string) ?? ""
    }
    if (name === "write" || name === "write_file") {
      return (tc.arguments.content as string) ?? ""
    }
    if (name === "list_directory" || name === "read" || name === "read_file") {
      const pathContent = [tc.arguments.path, tc.arguments.directory, tc.arguments.file_path].filter(Boolean).join(" ")
      return `${tc.tool_name} ${pathContent}`
    }
    return JSON.stringify(tc.arguments)
  }
}
