import { readdir, readFile, stat } from "node:fs/promises"
import path from "node:path"
import type { SecurityBaseline, SecurityConstraint } from "./types.ts"
import { compareRiskLevel, DEFAULT_FORBIDDEN_TOOLS, DEFAULT_FORBIDDEN_PATHS } from "./types.ts"
import type { PolicyRegistry } from "../policy/registry.ts"
import type { TaintTracker } from "../taint/tracker.ts"

const TOOL_CALL_PATTERNS = [
  /(?:use\s+)?tool[:\s]+(\w+)/gi,
  /call[_\s]*tool[:\s]*["']?(\w+)["']?/gi,
  /(?:execute|run|invoke)\s+(?:the\s+)?(\w+)\s+(?:tool|function)/gi,
  /\b(\w+)\s*\([^)]*\)\s*(?:\/\/|#|\/\*)?\s*(?:tool|function)/gi,
  /<tool_call[^>]*name=["'](\w+)["']/gi,
  /\btool_call\s*\(\s*["'](\w+)["']/gi,
]

const PATH_PATTERNS = [
  /(?:read|write|access|open|delete|edit|modify)\s+["']([^"']+)["']/gi,
  /(?:path|file|dir|directory)[:\s]+["']([^"']+)["']/gi,
  /["']([\/~][^"']+)["']/gi,
  /["']([A-Za-z]:[\\\/][^"']+)["']/gi,
]

const TAINT_SOURCE_PATTERNS = [
  /(?:user[_\s]*input|external[_\s]*data|untrusted[_\s]*source|api[_\s]*response)/gi,
  /(?:read|fetch|download|receive)\s+(?:from\s+)?(?:external|remote|user)/gi,
]

const TAINT_SINK_PATTERNS = [
  /(?:write|save|store|persist|execute|run)\s+(?:to\s+)?(?:local|file|system)/gi,
  /(?:exec|eval|system|shell)\s*\(/gi,
]

export class SkillSecurityScanner {
  constructor(
    private policyRegistry?: PolicyRegistry,
    private taintTracker?: TaintTracker,
  ) {}

  async scan(skillDir: string): Promise<SecurityBaseline> {
    const files = await this.readSkillFiles(skillDir)
    const allContent = files.map((f) => f.content).join("\n")

    const toolCalls = this.extractToolCalls(allContent)
    const pathPatterns = this.extractPathPatterns(allContent)
    const taintFlows = this.analyzeTaintFlows(allContent)
    const riskLevel = this.assessRiskLevel({
      toolCalls,
      pathPatterns,
      taintFlows,
      riskLevel: "low",
    })

    return {
      toolCalls: [...new Set(toolCalls)],
      pathPatterns: [...new Set(pathPatterns)],
      taintFlows,
      riskLevel,
    }
  }

  private async readSkillFiles(skillDir: string): Promise<{ path: string; content: string }[]> {
    const results: { path: string; content: string }[] = []
    const skillMdPath = path.join(skillDir, "SKILL.md")

    try {
      const skillContent = await readFile(skillMdPath, "utf-8")
      results.push({ path: skillMdPath, content: skillContent })
    } catch {
      // SKILL.md may not exist
    }

    try {
      const entries = await readdir(skillDir, { withFileTypes: true })
      for (const entry of entries) {
        if (entry.isFile() && (entry.name.endsWith(".md") || entry.name.endsWith(".ts") || entry.name.endsWith(".js") || entry.name.endsWith(".py"))) {
          const filePath = path.join(skillDir, entry.name)
          try {
            const content = await readFile(filePath, "utf-8")
            results.push({ path: filePath, content })
          } catch {
            // Skip files that can't be read
          }
        }
      }
    } catch {
      // Directory may not exist
    }

    return results
  }

  extractToolCalls(skillContent: string): string[] {
    const toolCalls: string[] = []

    for (const pattern of TOOL_CALL_PATTERNS) {
      let match
      while ((match = pattern.exec(skillContent)) !== null) {
        if (match[1]) {
          toolCalls.push(match[1].toLowerCase())
        }
      }
    }

    return [...new Set(toolCalls)]
  }

  extractPathPatterns(skillContent: string): string[] {
    const paths: string[] = []

    for (const pattern of PATH_PATTERNS) {
      let match
      while ((match = pattern.exec(skillContent)) !== null) {
        if (match[1]) {
          paths.push(match[1])
        }
      }
    }

    return [...new Set(paths)]
  }

  analyzeTaintFlows(skillContent: string): { source: string; sink: string }[] {
    const flows: { source: string; sink: string }[] = []
    const sources: string[] = []
    const sinks: string[] = []

    for (const pattern of TAINT_SOURCE_PATTERNS) {
      let match
      while ((match = pattern.exec(skillContent)) !== null) {
        sources.push(match[0])
      }
    }

    for (const pattern of TAINT_SINK_PATTERNS) {
      let match
      while ((match = pattern.exec(skillContent)) !== null) {
        sinks.push(match[0])
      }
    }

    for (const source of sources) {
      for (const sink of sinks) {
        flows.push({ source: source.trim(), sink: sink.trim() })
      }
    }

    return flows
  }

  assessRiskLevel(baseline: SecurityBaseline): "low" | "medium" | "high" {
    let riskScore = 0

    const dangerousTools = baseline.toolCalls.filter((tool) =>
      DEFAULT_FORBIDDEN_TOOLS.includes(tool.toLowerCase()),
    )
    riskScore += dangerousTools.length * 2

    const sensitivePaths = baseline.pathPatterns.filter((p) =>
      DEFAULT_FORBIDDEN_PATHS.some((forbidden) =>
        p.includes(forbidden.replace("~", process.env.HOME || "")) ||
        p.toLowerCase().includes(forbidden.toLowerCase()),
      ),
    )
    riskScore += sensitivePaths.length * 2

    riskScore += baseline.taintFlows.length

    if (riskScore >= 5) return "high"
    if (riskScore >= 2) return "medium"
    return "low"
  }

  async scanFile(filePath: string): Promise<SecurityBaseline> {
    try {
      const content = await readFile(filePath, "utf-8")
      const toolCalls = this.extractToolCalls(content)
      const pathPatterns = this.extractPathPatterns(content)
      const taintFlows = this.analyzeTaintFlows(content)
      const riskLevel = this.assessRiskLevel({
        toolCalls,
        pathPatterns,
        taintFlows,
        riskLevel: "low",
      })

      return {
        toolCalls,
        pathPatterns,
        taintFlows,
        riskLevel,
      }
    } catch {
      return {
        toolCalls: [],
        pathPatterns: [],
        taintFlows: [],
        riskLevel: "low",
      }
    }
  }

  compareBaselines(
    original: SecurityBaseline,
    optimized: SecurityBaseline,
  ): {
    newToolCalls: string[]
    newPathPatterns: string[]
    newTaintFlows: { source: string; sink: string }[]
    riskIncreased: boolean
  } {
    const newToolCalls = optimized.toolCalls.filter(
      (t) => !original.toolCalls.includes(t),
    )

    const newPathPatterns = optimized.pathPatterns.filter(
      (p) => !original.pathPatterns.includes(p),
    )

    const newTaintFlows = optimized.taintFlows.filter(
      (flow) =>
        !original.taintFlows.some(
          (o) => o.source === flow.source && o.sink === flow.sink,
        ),
    )

    const riskIncreased = compareRiskLevel(optimized.riskLevel, original.riskLevel) > 0

    return {
      newToolCalls,
      newPathPatterns,
      newTaintFlows,
      riskIncreased,
    }
  }
}
