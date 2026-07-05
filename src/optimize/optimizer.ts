import { mkdir, readdir, copyFile, stat, rm, readFile } from "node:fs/promises"
import path from "node:path"
import { homedir } from "node:os"
import type {
  OptimizeConfig,
  OptimizeResult,
  OptimizeRound,
  SecurityBaseline,
  SecurityConstraint,
  OptimizeSubmission,
  OptimizationChange,
  HeadlessAgent,
  HeadlessAgentConfig,
  HeadlessAgentResult,
} from "./types.ts"
import { OptimizeSubmissionSchema, DEFAULT_SECURITY_CONSTRAINT } from "./types.ts"
import { SkillSecurityScanner } from "./scanner.ts"
import { SecurityConstraintInjector } from "./constraints.ts"
import { OptimizeSecurityVerifier, type VerifyResult } from "./verifier.ts"

export class SkillOptimizer {
  private scanner: SkillSecurityScanner
  private injector: SecurityConstraintInjector
  private verifier: OptimizeSecurityVerifier
  private originalBaseline: SecurityBaseline | null = null
  private constraints: SecurityConstraint
  private rounds: OptimizeRound[] = []
  private headlessAgent: HeadlessAgent | null

  constructor(private config: OptimizeConfig) {
    this.scanner = new SkillSecurityScanner()
    this.injector = new SecurityConstraintInjector()
    this.verifier = new OptimizeSecurityVerifier(this.scanner, this.injector)
    this.constraints = config.securityConstraints ?? DEFAULT_SECURITY_CONSTRAINT
    this.headlessAgent = config.headlessAgent ?? null
  }

  async optimize(): Promise<OptimizeResult> {
    this.originalBaseline = await this.scanner.scan(this.config.skillDir)
    this.constraints = this.injector.mergeConstraints(
      this.injector.generateConstraintsFromBaseline(this.originalBaseline),
      this.config.securityConstraints ?? {},
    )

    const proposalId = this.generateProposalId()
    const proposalDir = await this.createProposalDir(proposalId)

    await this.snapshotRound(proposalDir, 0, this.config.skillDir)

    let currentSkillDir = this.config.skillDir
    let bestRound = 0
    let bestScore = 0

    for (let round = 1; round <= this.config.rounds; round++) {
      const roundResult = await this.runRound(round, currentSkillDir, proposalDir)

      this.rounds.push(roundResult)

      if (roundResult.score > bestScore && roundResult.securityAuditResult === "passed") {
        bestScore = roundResult.score
        bestRound = round
      }

      if (roundResult.securityAuditResult === "blocked") {
        continue
      }

      if (roundResult.score >= 0.95) {
        break
      }

      const roundDir = path.join(proposalDir, `round-${round}`)
      if (await this.dirExists(roundDir)) {
        currentSkillDir = roundDir
      }
    }

    const securityApproved = this.rounds.every(
      (r) => r.securityAuditResult !== "blocked",
    )

    return {
      proposalId,
      bestRound,
      rounds: this.rounds,
      finalScore: bestScore,
      securityApproved,
    }
  }

  private async runRound(
    round: number,
    skillDir: string,
    proposalDir: string,
  ): Promise<OptimizeRound> {
    const previousRounds = this.rounds.filter((r) => r.round < round)

    const agentResult = await this.callOptimizerAgent(
      skillDir,
      this.constraints,
      previousRounds,
    )

    const roundDir = path.join(proposalDir, `round-${round}`)
    await this.applyChanges(roundDir, skillDir, agentResult.changes)

    const score = await this.evaluateRound(roundDir)

    const verifyResult = await this.verifier.verify(
      this.originalBaseline!,
      roundDir,
    )

    const securityAuditResult = this.determineAuditResult(verifyResult)
    const securityRisks = verifyResult.newRisks

    return {
      round,
      score,
      changes: agentResult.changes.map((c) => c.description),
      securityAuditResult,
      securityRisks,
    }
  }

  private async callOptimizerAgent(
    skillDir: string,
    constraints: SecurityConstraint,
    previousRounds: OptimizeRound[],
  ): Promise<{ changes: OptimizationChange[]; newContent: string }> {
    const prompt = this.buildOptimizerPrompt(constraints, previousRounds)
    const agentConfig: HeadlessAgentConfig = {
      cwd: skillDir,
      prompt,
      model: this.config.optimizerModel,
      timeoutMs: 600_000,
    }

    const result = this.headlessAgent
      ? await this.headlessAgent.run(agentConfig)
      : await this.runHeadlessAgent(agentConfig)

    const submission = this.parseSubmission(result.rawStdout)

    return {
      changes: submission.changes ?? [],
      newContent: result.rawStdout,
    }
  }

  private buildOptimizerPrompt(
    constraints: SecurityConstraint,
    previousRounds: OptimizeRound[],
  ): string {
    const constraintInstructions = this.injector.generateConstraintInstructions(constraints)

    let historySection = ""
    if (previousRounds.length > 0) {
      historySection = `
## Previous Rounds

${previousRounds.map((r) => `
### Round ${r.round}
- Score: ${r.score.toFixed(3)}
- Changes: ${r.changes.join(", ")}
- Security Status: ${r.securityAuditResult}
`).join("\n")}

Do not repeat diagnoses that previous rounds tried and failed to improve.
`
    }

    return `You are a skill optimization agent.

A "skill" is a markdown instruction file (SKILL.md) plus optional bundle files
that guide an LLM agent when performing tasks. Your job is to analyze the skill
and improve it so that agents perform better on similar tasks in the future.

${constraintInstructions}

## Your Workspace

Your current directory is a complete copy of the skill folder. Edit any file
here using your normal tools (read, edit, write, glob, grep, bash). The files
you leave behind when you finish ARE the optimized skill.

## Method

1. Read the skill files (SKILL.md is the entry point).
2. Identify areas for improvement.
3. Make targeted edits that generalize beyond specific tasks.
4. Ensure all security constraints are maintained.
${historySection}
## Output Format

Write a JSON object with your structured summary:

\`\`\`json
{
  "rootCause": "description of the underlying problem",
  "reasoning": "full analysis of why this fix addresses the root cause",
  "confidence": 0.8,
  "changedFiles": ["SKILL.md"],
  "changes": [
    {
      "file": "SKILL.md",
      "section": "workflow",
      "description": "what and why of this change",
      "generality": "how this change helps other tasks"
    }
  ]
}
\`\`\`

If you determine the skill needs no changes, write:
\`\`\`json
{"noChanges": true}
\`\`\`

## Hard Rules

- **Task-content-agnostic**: Do NOT hard-code values or examples from specific tasks.
- **Security-first**: All security constraints must be maintained.
- **Be concise**: Prefer rewriting existing sections to appending new ones.
- **Diagnose before prescribing**: Know the root cause before you write any edits.
`
  }

  private async runHeadlessAgent(config: HeadlessAgentConfig): Promise<HeadlessAgentResult> {
    const start = Date.now()

    const cmd = [
      "opencode",
      "run",
      `IMPORTANT: Do not ask clarifying questions. Proceed directly.\n\n${config.prompt}`,
      "--dir", config.cwd,
      "--model", config.model,
      "--agent", "build",
      "--pure",
      "--format", "json",
    ]

    try {
      const proc = Bun.spawn(cmd, {
        cwd: config.cwd,
        stdout: "pipe",
        stderr: "pipe",
      })

      let timedOut = false
      let timer: ReturnType<typeof setTimeout> | undefined

      if (config.timeoutMs) {
        timer = setTimeout(() => {
          timedOut = true
          proc.kill()
        }, config.timeoutMs)
      }

      const [exitCode, stdout, stderr] = await Promise.all([
        proc.exited.then((code) => {
          if (timer) clearTimeout(timer)
          return code
        }),
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
      ])

      const durationMs = Date.now() - start

      return {
        exitCode,
        durationMs,
        cost: 0,
        tokens: { input: 0, output: 0 },
        rawStdout: stdout,
        rawStderr: stderr,
      }
    } catch (error) {
      return {
        exitCode: 1,
        durationMs: Date.now() - start,
        cost: 0,
        tokens: { input: 0, output: 0 },
        rawStdout: "",
        rawStderr: error instanceof Error ? error.message : String(error),
      }
    }
  }

  private parseSubmission(output: string): OptimizeSubmission {
    try {
      const jsonMatch = output.match(/```json\s*([\s\S]*?)\s*```/)
      if (jsonMatch && jsonMatch[1]) {
        const parsed = JSON.parse(jsonMatch[1])
        return OptimizeSubmissionSchema.parse(parsed)
      }

      const jsonObjectMatch = output.match(/\{[\s\S]*\}/)
      if (jsonObjectMatch) {
        const parsed = JSON.parse(jsonObjectMatch[0])
        return OptimizeSubmissionSchema.parse(parsed)
      }
    } catch {
      // Parse error
    }

    return {
      rootCause: "",
      reasoning: "",
      confidence: 0,
      changedFiles: [],
      changes: [],
      noChanges: true,
    }
  }

  /**
   * Metric 反映 SKILL.md 质量（vs 历史"工具数量越多越好"的反向设计）。
   * 维度：风险低 + taint 少 + 结构化好 + 工具适度（1-5 个为佳，0 或 10+ 都扣分）。
   * 与 SkVM task-level metric 仍有差距（这里仍是文件层），但能区分高质量 vs 低质量 SKILL.md。
   */
  private async evaluateRound(skillDir: string): Promise<number> {
    const baseline = await this.scanner.scan(skillDir)

    // riskScore: 风险越低分越高（high=0, medium=0.5, low=1）
    const riskScore =
      baseline.riskLevel === "high" ? 0 : baseline.riskLevel === "medium" ? 0.5 : 1

    // taintScore: taint flows 越少分越高
    const taintScore = 1 - Math.min(baseline.taintFlows.length / 5, 1)

    // structureScore: SKILL.md 标准化 section 数（# title, ## Workflow, ## Output, ## Security, ## Severity 等）
    const structureScore = await this.evaluateStructure(skillDir)

    // toolBalanceScore: 1-5 个工具为佳（太少=未指导 agent，太多=过度复杂）
    const toolCount = baseline.toolCalls.length
    const toolBalanceScore =
      toolCount === 0
        ? 0.3
        : toolCount <= 5
          ? 1
          : Math.max(0, 1 - (toolCount - 5) / 10)

    const score =
      riskScore * 0.35 +
      structureScore * 0.35 +
      taintScore * 0.2 +
      toolBalanceScore * 0.1

    return Math.max(0, Math.min(1, score))
  }

  private async evaluateStructure(skillDir: string): Promise<number> {
    try {
      const skillContent = await readFile(path.join(skillDir, "SKILL.md"), "utf-8")
      const standardSections = [
        /^#\s+\S/m, // 主标题
        /^##\s+Workflow/mi,
        /^##\s+Output/mi,
        /^##\s+(Security|Constraints)/mi,
        /^##\s+(Severity|Priorit)/mi,
        /^##\s+(Method|Steps|Process)/mi,
        /^##\s+(Vulnerability|Categories|Types)/mi,
      ]
      let count = 0
      for (const re of standardSections) {
        if (re.test(skillContent)) count++
      }
      return Math.min(1, count / 4) // 4 个 section 即满分
    } catch {
      return 0
    }
  }

  private determineAuditResult(verifyResult: VerifyResult): "passed" | "blocked" | "warning" {
    if (!verifyResult.approved) {
      return "blocked"
    }
    if (verifyResult.requiresManualReview) {
      return "warning"
    }
    return "passed"
  }

  private async applyChanges(
    targetDir: string,
    sourceDir: string,
    changes: OptimizationChange[],
  ): Promise<void> {
    await this.copyDir(sourceDir, targetDir)
  }

  private async copyDir(src: string, dest: string): Promise<void> {
    await mkdir(dest, { recursive: true })
    const entries = await readdir(src, { withFileTypes: true })

    for (const entry of entries) {
      const srcPath = path.join(src, entry.name)
      const destPath = path.join(dest, entry.name)

      if (entry.isDirectory()) {
        await this.copyDir(srcPath, destPath)
      } else if (entry.isFile()) {
        await copyFile(srcPath, destPath)
      }
    }
  }

  private generateProposalId(): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-")
    const random = Math.random().toString(36).substring(2, 8)
    return `${this.config.skillId}-${timestamp}-${random}`
  }

  private async createProposalDir(proposalId: string): Promise<string> {
    const baseDir = path.join(homedir(), ".skvm", "proposals", "jit-optimize")
    const proposalDir = path.join(
      baseDir,
      this.config.targetModel.replace(/\//g, "-"),
      this.config.optimizerModel.replace(/\//g, "-"),
      this.config.skillId,
      proposalId,
    )
    await mkdir(proposalDir, { recursive: true })
    return proposalDir
  }

  private async snapshotRound(
    proposalDir: string,
    round: number,
    skillDir: string,
  ): Promise<void> {
    const roundDir = path.join(proposalDir, `round-${round}`)
    await this.copyDir(skillDir, roundDir)
  }

  private async dirExists(p: string): Promise<boolean> {
    try {
      const s = await stat(p)
      return s.isDirectory()
    } catch {
      return false
    }
  }

  private selectBestRound(): number {
    const validRounds = this.rounds.filter(
      (r) => r.securityAuditResult !== "blocked",
    )

    if (validRounds.length === 0) {
      return 0
    }

    const sorted = [...validRounds].sort((a, b) => b.score - a.score)
    return sorted[0]!.round
  }
}
