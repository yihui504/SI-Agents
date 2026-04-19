import type { PolicyRegistry } from "../policy/registry.ts"
import type { TaintTracker } from "../taint/tracker.ts"
import type { BoostCandidate, SecurityAuditResult } from "./types.ts"

const DANGEROUS_PATTERNS = [
  { pattern: /\beval\s*\(/gi, warning: "Template contains eval() which can execute arbitrary code" },
  { pattern: /\bFunction\s*\(/gi, warning: "Template contains Function() constructor which can execute arbitrary code" },
  { pattern: /\brequire\s*\(\s*['"]child_process['"]\s*\)/gi, warning: "Template imports child_process which can spawn processes" },
  { pattern: /\bimport\s+.*\s+from\s+['"]child_process['"]/gi, warning: "Template imports child_process which can spawn processes" },
  { pattern: /\bprocess\.env\b/gi, warning: "Template accesses process.env which may expose secrets" },
  { pattern: /\brm\s+-rf\b/gi, warning: "Template contains 'rm -rf' which is destructive" },
  { pattern: /\bdd\s+if=/gi, warning: "Template contains 'dd' command which can be destructive" },
  { pattern: />\s*\/dev\/(sda|hda|nvme)/gi, warning: "Template writes to disk device directly" },
  { pattern: /\bcurl\s+.*\|\s*(ba)?sh\b/gi, warning: "Template pipes curl output to shell which is dangerous" },
  { pattern: /\bwget\s+.*\|\s*(ba)?sh\b/gi, warning: "Template pipes wget output to shell which is dangerous" },
]

const SENSITIVE_PATHS = [
  "/etc/passwd",
  "/etc/shadow",
  "/etc/ssh/",
  "~/.ssh/",
  "~/.gnupg/",
  "~/.aws/",
  "~/.env",
  ".env",
]

export class BoostSecurityAuditor {
  constructor(
    private policyRegistry: PolicyRegistry,
    private taintTracker: TaintTracker,
  ) {}

  async auditBeforeExecution(
    candidate: BoostCandidate,
    params: Record<string, unknown>,
  ): Promise<SecurityAuditResult> {
    const templateSafety = this.checkTemplateSafety(candidate.functionTemplate)
    if (!templateSafety.safe) {
      return {
        passed: false,
        reason: `Template safety check failed: ${templateSafety.warnings.join("; ")}`,
        warnings: templateSafety.warnings,
      }
    }

    const toolCalls = this.extractToolCallsFromTemplate(candidate.functionTemplate, params)
    if (toolCalls.length === 0) {
      return { passed: true, warnings: templateSafety.warnings }
    }

    const blockedRules: string[] = []

    for (const tc of toolCalls) {
      const instruction = this.buildMockInstruction(tc)
      this.taintTracker.setBaseTaint(instruction, tc.toolName, tc.args)

      const taintResult = this.taintTracker.checkTaintPolicy(tc.toolName, tc.args, instruction)
      if (!taintResult.allowed) {
        blockedRules.push(`Taint policy blocked ${tc.toolName}: ${taintResult.reason}`)
      }
    }

    if (blockedRules.length > 0) {
      return {
        passed: false,
        reason: `Security policies blocked execution`,
        blockedRules,
        warnings: templateSafety.warnings,
      }
    }

    return { passed: true, warnings: templateSafety.warnings }
  }

  async auditAfterExecution(candidate: BoostCandidate, result: unknown): Promise<SecurityAuditResult> {
    if (result === null || result === undefined) {
      return { passed: true }
    }

    const resultStr = typeof result === "string" ? result : JSON.stringify(result)
    const hasSensitiveData = this.checkForSensitiveData(resultStr)

    if (hasSensitiveData) {
      return {
        passed: false,
        reason: "Execution result contains potentially sensitive data",
        warnings: ["Result may contain sensitive information that should not be exposed"],
      }
    }

    return { passed: true }
  }

  checkTemplateSafety(template: string): { safe: boolean; warnings: string[] } {
    const warnings: string[] = []

    for (const { pattern, warning } of DANGEROUS_PATTERNS) {
      if (pattern.test(template)) {
        warnings.push(warning)
      }
    }

    for (const sensitivePath of SENSITIVE_PATHS) {
      if (template.toLowerCase().includes(sensitivePath.toLowerCase())) {
        warnings.push(`Template references sensitive path: ${sensitivePath}`)
      }
    }

    const hasUnescapedInput = this.checkForUnescapedInput(template)
    if (hasUnescapedInput) {
      warnings.push("Template may have unescaped user input which could lead to injection")
    }

    return {
      safe: warnings.length === 0,
      warnings,
    }
  }

  private extractToolCallsFromTemplate(
    template: string,
    params: Record<string, unknown>,
  ): Array<{ toolName: string; args: Record<string, unknown> }> {
    const toolCalls: Array<{ toolName: string; args: Record<string, unknown> }> = []
    const execMatch = template.match(/exec|execute_command|run/i)
    if (execMatch) {
      const command = this.instantiateTemplate(template, params)
      toolCalls.push({
        toolName: "exec",
        args: { command },
      })
    }
    const writeMatch = template.match(/write|edit|save/i)
    if (writeMatch) {
      toolCalls.push({
        toolName: "write",
        args: { content: this.instantiateTemplate(template, params) },
      })
    }
    return toolCalls
  }

  private instantiateTemplate(template: string, params: Record<string, unknown>): string {
    let result = template
    for (const [key, value] of Object.entries(params)) {
      result = result.replaceAll(`\${${key}}`, String(value))
    }
    return result
  }

  private buildMockInstruction(toolCall: { toolName: string; args: Record<string, unknown> }): Record<string, unknown> {
    return {
      id: `mock-${Date.now()}`,
      instruction_type: "EXEC",
      instruction_category: "EXECUTION.Env",
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
      content: {
        tool_name: toolCall.toolName,
        tool_call_id: `mock-tc-${Date.now()}`,
        arguments: toolCall.args,
      },
    }
  }

  private checkForSensitiveData(content: string): boolean {
    const sensitivePatterns = [
      /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/i,
      /-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/i,
      /aws_access_key_id\s*=\s*[A-Z0-9]{20}/i,
      /aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}/i,
      /api[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9]{20,}['"]?/i,
      /password\s*[:=]\s*['"]?[^\s'"]{8,}['"]?/i,
      /secret[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9]{16,}['"]?/i,
      /Bearer\s+[A-Za-z0-9\-._~+/]+=*/i,
      /sk-[a-zA-Z0-9]{20,}/,
    ]

    for (const pattern of sensitivePatterns) {
      if (pattern.test(content)) {
        return true
      }
    }

    return false
  }

  private checkForUnescapedInput(template: string): boolean {
    const paramRefs = template.match(/\$\{[^}]+\}/g) || []
    for (const ref of paramRefs) {
      const paramName = ref.slice(2, -1)
      const beforeParam = template.split(ref)[0]
      const lastQuote = Math.max(
        beforeParam.lastIndexOf('"'),
        beforeParam.lastIndexOf("'"),
        beforeParam.lastIndexOf("`"),
      )
      const lastSpace = beforeParam.lastIndexOf(" ")
      if (lastQuote > lastSpace && lastQuote > beforeParam.length - 50) {
        const afterRef = template.split(ref)[1] || ""
        const nextQuote = Math.min(
          afterRef.indexOf('"') === -1 ? Infinity : afterRef.indexOf('"'),
          afterRef.indexOf("'") === -1 ? Infinity : afterRef.indexOf("'"),
          afterRef.indexOf("`") === -1 ? Infinity : afterRef.indexOf("`"),
        )
        if (nextQuote < 5) {
          continue
        }
      }
    }
    return false
  }
}
