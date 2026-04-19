import type { SecurityBaseline, SecurityConstraint } from "./types.ts"
import { compareRiskLevel, DEFAULT_SECURITY_CONSTRAINT } from "./types.ts"

export class SecurityConstraintInjector {
  generateConstraintInstructions(constraints: SecurityConstraint): string {
    const sections: string[] = []

    sections.push("## Security Constraints")
    sections.push("")
    sections.push("You MUST adhere to the following security constraints during optimization:")
    sections.push("")

    if (constraints.forbiddenTools.length > 0) {
      sections.push("### Forbidden Tool Calls")
      sections.push("")
      sections.push("The following tool calls are FORBIDDEN and must NOT be introduced in the optimized skill:")
      sections.push("")
      for (const tool of constraints.forbiddenTools) {
        sections.push(`- \`${tool}\``)
      }
      sections.push("")
    }

    if (constraints.forbiddenPaths.length > 0) {
      sections.push("### Forbidden Path Access")
      sections.push("")
      sections.push("The following paths are FORBIDDEN and must NOT be accessed in the optimized skill:")
      sections.push("")
      for (const path of constraints.forbiddenPaths) {
        sections.push(`- \`${path}\``)
      }
      sections.push("")
    }

    if (constraints.requiredTaintRules.length > 0) {
      sections.push("### Required Taint Propagation Rules")
      sections.push("")
      sections.push("The following taint propagation rules MUST be maintained:")
      sections.push("")
      for (const rule of constraints.requiredTaintRules) {
        sections.push(`- ${rule}`)
      }
      sections.push("")
    }

    sections.push("### Maximum Risk Level")
    sections.push("")
    sections.push(`The optimized skill must NOT exceed a risk level of **${constraints.maxRiskLevel.toUpperCase()}**.`)
    sections.push("")

    sections.push("### Security Verification")
    sections.push("")
    sections.push("After making any changes, verify that:")
    sections.push("1. No forbidden tool calls have been introduced")
    sections.push("2. No forbidden paths are accessed")
    sections.push("3. All required taint propagation rules are maintained")
    sections.push("4. The risk level does not exceed the maximum allowed")
    sections.push("")

    return sections.join("\n")
  }

  generateConstraintsFromBaseline(baseline: SecurityBaseline): SecurityConstraint {
    const forbiddenTools: string[] = [...DEFAULT_SECURITY_CONSTRAINT.forbiddenTools]
    const forbiddenPaths: string[] = [...DEFAULT_SECURITY_CONSTRAINT.forbiddenPaths]
    const requiredTaintRules: string[] = []

    for (const tool of baseline.toolCalls) {
      if (this.isDangerousTool(tool) && !forbiddenTools.includes(tool)) {
        forbiddenTools.push(tool)
      }
    }

    for (const path of baseline.pathPatterns) {
      if (this.isSensitivePath(path) && !forbiddenPaths.includes(path)) {
        forbiddenPaths.push(path)
      }
    }

    for (const flow of baseline.taintFlows) {
      const rule = `External data from "${flow.source}" must NOT be directly written to "${flow.sink}" without validation`
      if (!requiredTaintRules.includes(rule)) {
        requiredTaintRules.push(rule)
      }
    }

    const maxRiskLevel = this.determineMaxRiskLevel(baseline.riskLevel)

    return {
      forbiddenTools,
      forbiddenPaths,
      requiredTaintRules,
      maxRiskLevel,
    }
  }

  validateAgainstConstraints(
    optimizedSkill: string,
    constraints: SecurityConstraint,
  ): { valid: boolean; violations: string[] } {
    const violations: string[] = []

    const toolCallPattern = /(?:tool|function|call)[:\s]+["']?(\w+)["']?/gi
    let match
    while ((match = toolCallPattern.exec(optimizedSkill)) !== null) {
      const tool = match[1]?.toLowerCase()
      if (tool && constraints.forbiddenTools.includes(tool)) {
        violations.push(`Forbidden tool call detected: ${tool}`)
      }
    }

    const pathPattern = /["']([\/~][^"']+)["']/g
    while ((match = pathPattern.exec(optimizedSkill)) !== null) {
      const path = match[1]
      if (path) {
        for (const forbidden of constraints.forbiddenPaths) {
          if (path.includes(forbidden) || path.toLowerCase().includes(forbidden.toLowerCase())) {
            violations.push(`Forbidden path access detected: ${path}`)
            break
          }
        }
      }
    }

    for (const rule of constraints.requiredTaintRules) {
      const sourceMatch = rule.match(/from ["'](.+?)["']/)
      const sinkMatch = rule.match(/to ["'](.+?)["']/)
      if (sourceMatch && sinkMatch) {
        const source = sourceMatch[1]
        const sink = sinkMatch[1]
        if (source && sink) {
          const directFlowPattern = new RegExp(
            `${this.escapeRegex(source)}[^\\n]*${this.escapeRegex(sink)}`,
            "gi",
          )
          if (directFlowPattern.test(optimizedSkill)) {
            violations.push(`Taint rule violation: ${rule}`)
          }
        }
      }
    }

    return {
      valid: violations.length === 0,
      violations,
    }
  }

  private isDangerousTool(tool: string): boolean {
    const dangerousTools = [
      "exec", "execute", "run", "shell", "bash", "cmd", "powershell",
      "delete", "remove", "rm", "unlink", "rmdir",
      "format", "wipe", "destroy",
      "shutdown", "reboot", "restart",
      "kill", "terminate", "abort",
      "sudo", "su", "doas",
      "chmod", "chown", "chgrp",
    ]
    return dangerousTools.some((d) => tool.toLowerCase().includes(d))
  }

  private isSensitivePath(path: string): boolean {
    const sensitivePatterns = [
      "/etc/passwd", "/etc/shadow", "/etc/sudoers",
      "~/.ssh/", "~/.gnupg/", "~/.ssh/",
      "/root/", "/proc/", "/sys/",
      "id_rsa", "id_ed25519", ".pem", ".key",
      "credentials", "secrets", ".env",
    ]
    return sensitivePatterns.some((p) =>
      path.toLowerCase().includes(p.toLowerCase()),
    )
  }

  private determineMaxRiskLevel(currentLevel: string): "low" | "medium" | "high" {
    if (compareRiskLevel(currentLevel, "high") >= 0) {
      return "high"
    }
    if (compareRiskLevel(currentLevel, "medium") >= 0) {
      return "medium"
    }
    return "low"
  }

  private escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  }

  mergeConstraints(
    base: SecurityConstraint,
    override: Partial<SecurityConstraint>,
  ): SecurityConstraint {
    return {
      forbiddenTools: override.forbiddenTools ?? base.forbiddenTools,
      forbiddenPaths: override.forbiddenPaths ?? base.forbiddenPaths,
      requiredTaintRules: override.requiredTaintRules ?? base.requiredTaintRules,
      maxRiskLevel: override.maxRiskLevel ?? base.maxRiskLevel,
    }
  }
}
