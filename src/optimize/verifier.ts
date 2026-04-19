import type { SecurityBaseline } from "./types.ts"
import { compareRiskLevel } from "./types.ts"
import { SkillSecurityScanner } from "./scanner.ts"
import { SecurityConstraintInjector } from "./constraints.ts"
import { NanobotPolicy, type NanobotPolicyConfig } from "../policy/nanobot.ts"
import { readFile } from "node:fs/promises"
import path from "node:path"

// Default dangerous command patterns for skill optimization
const DEFAULT_EXEC_DENY_PATTERNS = [
  "rm -rf",
  "rm -rf /",
  "rm -rf ~",
  "sudo rm",
  "chmod 777",
  "chmod -R 777",
  "chown -R",
  "dd if=",
  "mkfs",
  "format",
  "shutdown",
  "reboot",
  "init 0",
  "halt",
  "poweroff",
  "> /dev/sd",
  ":(){ :|:& };:",
  "curl | bash",
  "wget | bash",
  "curl | sh",
  "wget | sh",
  "/etc/passwd",
  "/etc/shadow",
  "DROP TABLE",
  "DROP DATABASE",
  "TRUNCATE TABLE",
  "DELETE FROM",
]

export interface VerifyResult {
  approved: boolean
  newRisks: string[]
  riskLevel: "low" | "medium" | "high"
  requiresManualReview: boolean
  violations: string[]
  comparison: {
    newToolCalls: string[]
    newPathPatterns: string[]
    newTaintFlows: { source: string; sink: string }[]
    riskIncreased: boolean
  }
}

export interface CommandSafetyResult {
  safe: boolean
  violations: string[]
}

export class OptimizeSecurityVerifier {
  private nanobotPolicy: NanobotPolicy

  constructor(
    private scanner: SkillSecurityScanner,
    private injector: SecurityConstraintInjector,
    nanobotConfig?: NanobotPolicyConfig,
  ) {
    // Initialize NanobotPolicy with default or custom config
    this.nanobotPolicy = new NanobotPolicy({
      enabled: true,
      execDenyPatterns: nanobotConfig?.execDenyPatterns ?? DEFAULT_EXEC_DENY_PATTERNS,
    })
  }

  async verify(
    originalBaseline: SecurityBaseline,
    optimizedSkillDir: string,
  ): Promise<VerifyResult> {
    const optimizedBaseline = await this.scanner.scan(optimizedSkillDir)
    const comparison = this.scanner.compareBaselines(originalBaseline, optimizedBaseline)
    const newRisks = this.detectNewRisks(originalBaseline, optimizedBaseline, comparison)
    const constraints = this.injector.generateConstraintsFromBaseline(originalBaseline)

    const violations: string[] = []

    for (const tool of comparison.newToolCalls) {
      if (constraints.forbiddenTools.includes(tool)) {
        violations.push(`New forbidden tool call: ${tool}`)
      }
    }

    for (const path of comparison.newPathPatterns) {
      for (const forbidden of constraints.forbiddenPaths) {
        if (path.includes(forbidden)) {
          violations.push(`New forbidden path access: ${path}`)
          break
        }
      }
    }

    for (const flow of comparison.newTaintFlows) {
      violations.push(`New taint flow: ${flow.source} -> ${flow.sink}`)
    }

    if (compareRiskLevel(optimizedBaseline.riskLevel, constraints.maxRiskLevel) > 0) {
      violations.push(
        `Risk level exceeded: ${optimizedBaseline.riskLevel} > ${constraints.maxRiskLevel}`,
      )
    }

    // Integrate NanobotPolicy command safety check
    const commandSafetyResult = await this.verifyCommandSafety(optimizedSkillDir)
    if (!commandSafetyResult.safe) {
      violations.push(...commandSafetyResult.violations)
    }

    const approved = violations.length === 0 && !comparison.riskIncreased
    const requiresManualReview = this.needsManualReview({
      approved,
      newRisks,
      violations,
    })

    return {
      approved,
      newRisks,
      riskLevel: optimizedBaseline.riskLevel,
      requiresManualReview,
      violations,
      comparison,
    }
  }

  detectNewRisks(
    original: SecurityBaseline,
    optimized: SecurityBaseline,
    comparison: {
      newToolCalls: string[]
      newPathPatterns: string[]
      newTaintFlows: { source: string; sink: string }[]
      riskIncreased: boolean
    },
  ): string[] {
    const risks: string[] = []

    for (const tool of comparison.newToolCalls) {
      risks.push(`New tool call introduced: ${tool}`)
    }

    for (const path of comparison.newPathPatterns) {
      risks.push(`New path pattern introduced: ${path}`)
    }

    for (const flow of comparison.newTaintFlows) {
      risks.push(`New taint flow detected: ${flow.source} -> ${flow.sink}`)
    }

    if (comparison.riskIncreased) {
      risks.push(
        `Risk level increased from ${original.riskLevel} to ${optimized.riskLevel}`,
      )
    }

    return risks
  }

  needsManualReview(result: {
    approved: boolean
    newRisks: string[]
    violations: string[]
  }): boolean {
    if (!result.approved) {
      return true
    }

    if (result.newRisks.length > 0) {
      return true
    }

    const highRiskKeywords = [
      "exec", "shell", "bash", "cmd", "powershell",
      "delete", "remove", "rm",
      "format", "wipe",
      "/etc/", "/root/", "~/.ssh/",
      "password", "secret", "key", "credential",
    ]

    for (const risk of result.newRisks) {
      for (const keyword of highRiskKeywords) {
        if (risk.toLowerCase().includes(keyword)) {
          return true
        }
      }
    }

    return false
  }

  /**
   * Verify command safety in skill files using NanobotPolicy
   * Scans skill files for command execution patterns and checks against deny patterns
   */
  async verifyCommandSafety(skillDir: string): Promise<CommandSafetyResult> {
    const violations: string[] = []

    try {
      // Read all skill files in the directory
      const files = await this.readSkillFiles(skillDir)

      for (const file of files) {
        const commandViolations = await this.checkFileForDangerousCommands(file.path, file.content)
        violations.push(...commandViolations)
      }
    } catch (error) {
      // If we can't read the files, we should still return a result
      violations.push(`Warning: Could not verify command safety - ${error}`)
    }

    return {
      safe: violations.length === 0,
      violations,
    }
  }

  /**
   * Read all skill files from a directory
   */
  private async readSkillFiles(skillDir: string): Promise<{ path: string; content: string }[]> {
    const results: { path: string; content: string }[] = []
    const { readdir, stat } = await import("node:fs/promises")

    // Try to read SKILL.md first
    const skillMdPath = path.join(skillDir, "SKILL.md")
    try {
      const skillContent = await readFile(skillMdPath, "utf-8")
      results.push({ path: skillMdPath, content: skillContent })
    } catch {
      // SKILL.md may not exist
    }

    // Read other relevant files
    try {
      const entries = await readdir(skillDir, { withFileTypes: true })
      for (const entry of entries) {
        if (entry.isFile() && (
          entry.name.endsWith(".md") ||
          entry.name.endsWith(".ts") ||
          entry.name.endsWith(".js") ||
          entry.name.endsWith(".py")
        )) {
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

  /**
   * Check a file's content for dangerous command patterns
   */
  private async checkFileForDangerousCommands(
    filePath: string,
    content: string,
  ): Promise<string[]> {
    const violations: string[] = []

    // Patterns to detect command execution in skill files
    const commandExecutionPatterns = [
      // Bash/shell command patterns
      /(?:run|execute|exec|call)\s+(?:command|shell|bash|cmd|powershell)\s*[:\s]+\s*["']([^"']+)["']/gi,
      /(?:command|cmd|shell|script)\s*[:\s]+\s*["']([^"']+)["']/gi,
      /`([^`]+)`/g,  // Backtick commands
      /\$\(([^)]+)\)/g,  // $() command substitution
      /<command[^>]*>([^<]+)<\/command>/gi,
      /<shell[^>]*>([^<]+)<\/shell>/gi,
      /```(?:bash|shell|sh|cmd|powershell)\s*\n([\s\S]*?)```/gi,
      // Tool call patterns
      /(?:tool_call|call_tool|invoke_tool)\s*\(\s*["'](?:exec|execute_command|run_command|shell|bash|terminal)["']\s*,\s*["']([^"']+)["']/gi,
      /"command"\s*:\s*"([^"]+)"/g,
      /'command'\s*:\s*'([^']+)'/g,
      // TypeScript/JavaScript variable assignment patterns
      /(?:const|let|var)\s+\w*\s*=\s*["']([^"']+)["']/gi,
      // String literals that might contain commands
      /["']([^"']*(?:rm|chmod|sudo|dd|mkfs|shutdown|reboot|curl|wget|DROP|DELETE)[^"']*)["']/gi,
    ]

    for (const pattern of commandExecutionPatterns) {
      let match
      while ((match = pattern.exec(content)) !== null) {
        const command = match[1] || match[0]

        // Use NanobotPolicy to check the command
        const checkResult = this.checkCommandWithPolicy(command)
        if (!checkResult.allowed) {
          const relativePath = filePath.replace(/\\/g, "/")
          violations.push(
            `Dangerous command in ${relativePath}: ${checkResult.message}`,
          )
        }
      }
    }

    return violations
  }

  /**
   * Check a single command against NanobotPolicy
   */
  private checkCommandWithPolicy(command: string): { allowed: boolean; message?: string } {
    return this.nanobotPolicy.checkCommand(command)
  }

  /**
   * Get the NanobotPolicy instance for external use
   */
  getNanobotPolicy(): NanobotPolicy {
    return this.nanobotPolicy
  }

  async verifyAgainstConstraints(
    optimizedSkillDir: string,
    constraints: SecurityBaseline,
  ): Promise<{
    compliant: boolean
    violations: string[]
    warnings: string[]
  }> {
    const baseline = await this.scanner.scan(optimizedSkillDir)
    const violations: string[] = []
    const warnings: string[] = []

    for (const tool of baseline.toolCalls) {
      if (constraints.toolCalls.includes(tool)) {
        warnings.push(`Tool call ${tool} matches existing baseline`)
      }
    }

    const constraintObj = this.injector.generateConstraintsFromBaseline(constraints)
    const validation = this.injector.validateAgainstConstraints(
      JSON.stringify(baseline),
      constraintObj,
    )

    violations.push(...validation.violations)

    return {
      compliant: violations.length === 0,
      violations,
      warnings,
    }
  }

  generateSecurityReport(result: VerifyResult): string {
    const lines: string[] = []

    lines.push("# Security Verification Report")
    lines.push("")
    lines.push("## Summary")
    lines.push("")
    lines.push(`- **Status**: ${result.approved ? "APPROVED" : "BLOCKED"}`)
    lines.push(`- **Risk Level**: ${result.riskLevel.toUpperCase()}`)
    lines.push(`- **Manual Review Required**: ${result.requiresManualReview ? "YES" : "NO"}`)
    lines.push("")

    if (result.violations.length > 0) {
      lines.push("## Violations")
      lines.push("")
      for (const v of result.violations) {
        lines.push(`- ${v}`)
      }
      lines.push("")
    }

    if (result.newRisks.length > 0) {
      lines.push("## New Risks Detected")
      lines.push("")
      for (const r of result.newRisks) {
        lines.push(`- ${r}`)
      }
      lines.push("")
    }

    lines.push("## Comparison Details")
    lines.push("")
    lines.push("### New Tool Calls")
    lines.push("")
    if (result.comparison.newToolCalls.length > 0) {
      for (const t of result.comparison.newToolCalls) {
        lines.push(`- ${t}`)
      }
    } else {
      lines.push("None")
    }
    lines.push("")

    lines.push("### New Path Patterns")
    lines.push("")
    if (result.comparison.newPathPatterns.length > 0) {
      for (const p of result.comparison.newPathPatterns) {
        lines.push(`- ${p}`)
      }
    } else {
      lines.push("None")
    }
    lines.push("")

    lines.push("### New Taint Flows")
    lines.push("")
    if (result.comparison.newTaintFlows.length > 0) {
      for (const f of result.comparison.newTaintFlows) {
        lines.push(`- ${f.source} -> ${f.sink}`)
      }
    } else {
      lines.push("None")
    }
    lines.push("")

    lines.push(`### Risk Level Change: ${result.comparison.riskIncreased ? "INCREASED" : "NO CHANGE"}`)
    lines.push("")

    return lines.join("\n")
  }
}
