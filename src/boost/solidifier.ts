import { spawn } from "node:child_process"
import type { PolicyRegistry } from "../policy/registry.ts"
import type { TaintTracker } from "../taint/tracker.ts"
import type { RuntimeHooks, BeforeLLMContext, BeforeLLMResult, AfterLLMContext, AfterRunContext } from "../types/hooks.ts"
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

/**
 * Prompt cache entry —— temp=0 下同 prompt 跑出相同回复，第二次直接返回 cached（跳过 LLM 循环）
 * 这是广谱 boost：不限 candidate keyword，对任何成功完成的 prompt 都生效（multi-step 任务也省）。
 * 安全：仅缓存 audit 通过的 run；cache key = prompt 全文 hash（避免跨任务误复用）。
 */
interface PromptCacheEntry {
  text: string
  promptHash: string
  hitCount: number
  createdAt: number
}

function hashPrompt(prompt: string): string {
  let h = 5381
  for (let i = 0; i < prompt.length; i++) {
    h = ((h << 5) + h + prompt.charCodeAt(i)) | 0
  }
  return `pc-${(h >>> 0).toString(36)}`
}

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
  private promptCache: Map<string, PromptCacheEntry> = new Map()
  private promptCacheEnabled: boolean
  // 记录最近一次 beforeLLM 的 prompt hash，供 afterRun 写 cache 时用
  // （bare-agent 的 runResultToRecord 不含 prompt，所以 Solidifier 自己记）
  private lastPromptHash: string | null = null

  constructor(config: SolidifierConfig, candidates: BoostCandidate[], savedState?: Map<string, SolidificationState>) {
    this.skillId = config.skillId
    this.candidates = candidates
    this.promotionThreshold = config.promotionThreshold ?? DEFAULT_PROMOTION_THRESHOLD
    this.demotionThreshold = config.demotionThreshold ?? DEFAULT_DEMOTION_THRESHOLD
    this.monitoredTools = config.monitoredTools ?? DEFAULT_MONITORED_TOOLS
    this.auditor = new BoostSecurityAuditor(config.policyRegistry, config.taintTracker)
    this.promptCacheEnabled = true // 广谱 boost：temp=0 下同 prompt 直接 cache hit

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
      // 广谱 boost：prompt cache 查询（temp=0 下同 prompt 第二次直接命中，跳过 LLM 循环）
      // 对 multi-step 非候选任务也生效——只要该 prompt 之前成功完成过
      if (this.promptCacheEnabled) {
        const promptHash = hashPrompt(ctx.prompt)
        this.lastPromptHash = promptHash
        const cached = this.promptCache.get(promptHash)
        if (cached) {
          cached.hitCount++
          return {
            action: "replace",
            toolResults: [],
            text: cached.text,
          }
        }
      }

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
              text: `Here is the result:\n\`\`\`\n${result.output}\n\`\`\``,
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

  /**
   * AfterRun hook —— run 成功后写 prompt cache（temp=0 下同 prompt 再来时直接命中）
   * 仅缓存 success=true 且有非空 finalText 的 run（避免缓存失败/policy block）
   * 这是广谱 boost 的写入端：对任何成功 prompt 都生效，不限 candidate
   */
  createAfterRunHook(): (ctx: AfterRunContext) => Promise<void> {
    return async (ctx: AfterRunContext): Promise<void> => {
      if (!this.promptCacheEnabled) return
      const result = ctx.result as Record<string, unknown>
      const success = ctx.success as boolean
      if (!success) return
      const text = (result.text as string) ?? ""
      if (!text || text.trim().length === 0) return
      // 跳过 policy-blocked / crashed 的 run
      const runStatus = (result.runStatus as string) ?? ""
      if (runStatus === "policy-blocked" || runStatus === "adapter-crashed" || runStatus === "timeout") return

      const promptHash = this.lastPromptHash
      this.lastPromptHash = null
      if (!promptHash) return
      if (!this.promptCache.has(promptHash)) {
        this.promptCache.set(promptHash, {
          text,
          promptHash,
          hitCount: 0,
          createdAt: Date.now(),
        })
      }
    }
  }

  getPromptCacheStats(): { size: number; totalHits: number } {
    let totalHits = 0
    for (const entry of this.promptCache.values()) {
      totalHits += entry.hitCount
    }
    return { size: this.promptCache.size, totalHits }
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
