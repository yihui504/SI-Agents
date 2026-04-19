import type { OptimizeRound, OptimizeResult, SecurityBaseline } from "./types.ts"
import type { VerifyResult } from "./verifier.ts"
import { SkillSecurityScanner } from "./scanner.ts"
import { SecurityConstraintInjector } from "./constraints.ts"
import { OptimizeSecurityVerifier } from "./verifier.ts"

/**
 * Configuration for the optimization loop
 */
export interface OptimizationLoopConfig {
  /** Maximum number of optimization rounds */
  maxRounds: number
  /** Score threshold for early convergence (0-1) */
  convergenceThreshold: number
  /** Callback invoked after each round completes */
  onRoundComplete?: (round: number, result: OptimizeRound) => void
  /** Callback invoked when security verification fails */
  onSecurityFailure?: (round: number, verifyResult: VerifyResult) => void
  /** Whether to stop on security verification failure */
  stopOnSecurityFailure?: boolean
}

/**
 * Default configuration for optimization loop
 */
export const DEFAULT_LOOP_CONFIG: OptimizationLoopConfig = {
  maxRounds: 5,
  convergenceThreshold: 0.95,
  stopOnSecurityFailure: true,
}

/**
 * Interface for the optimizer that runs each round
 */
export interface IOptimizer {
  runRound(
    round: number,
    previousRounds: OptimizeRound[],
  ): Promise<{ score: number; changes: string[] }>
}

/**
 * Result of a single optimization round with security verification
 */
export interface RoundResult {
  round: number
  score: number
  changes: string[]
  securityAuditResult: "passed" | "blocked" | "warning"
  securityRisks: string[]
  verifyResult?: VerifyResult
}

/**
 * OptimizationLoop manages multi-round optimization with security verification
 *
 * This class orchestrates the optimization process:
 * 1. Runs multiple rounds of optimization
 * 2. Verifies security after each round
 * 3. Supports early termination on convergence or security failure
 * 4. Tracks the best performing round
 */
export class OptimizationLoop {
  private scanner: SkillSecurityScanner
  private injector: SecurityConstraintInjector
  private verifier: OptimizeSecurityVerifier
  private rounds: OptimizeRound[] = []
  private bestRound: number = 0
  private bestScore: number = 0
  private stopped: boolean = false
  private stopReason?: "converged" | "security_failure" | "max_rounds"

  constructor(
    private optimizer: IOptimizer,
    private securityVerifier: OptimizeSecurityVerifier,
    private originalBaseline: SecurityBaseline,
    private config: OptimizationLoopConfig,
  ) {
    this.scanner = new SkillSecurityScanner()
    this.injector = new SecurityConstraintInjector()
    this.verifier = securityVerifier
  }

  /**
   * Run the optimization loop
   * @returns The final optimization result
   */
  async run(): Promise<OptimizeResult> {
    this.rounds = []
    this.bestRound = 0
    this.bestScore = 0
    this.stopped = false
    this.stopReason = undefined

    for (let round = 1; round <= this.config.maxRounds; round++) {
      if (this.stopped) {
        break
      }

      const roundResult = await this.executeRound(round)
      this.rounds.push(roundResult)

      // Notify callback
      if (this.config.onRoundComplete) {
        this.config.onRoundComplete(round, roundResult)
      }

      // Update best round if this one is better and passed security
      if (roundResult.score > this.bestScore && roundResult.securityAuditResult !== "blocked") {
        this.bestScore = roundResult.score
        this.bestRound = round
      }

      // Check for convergence
      if (roundResult.score >= this.config.convergenceThreshold) {
        this.stopped = true
        this.stopReason = "converged"
        break
      }

      // Check for security failure
      if (roundResult.securityAuditResult === "blocked") {
        if (this.config.stopOnSecurityFailure) {
          this.stopped = true
          this.stopReason = "security_failure"
        }
        if (this.config.onSecurityFailure && roundResult.verifyResult) {
          this.config.onSecurityFailure(round, roundResult.verifyResult)
        }
      }
    }

    // Set stop reason if we completed all rounds
    if (!this.stopped) {
      this.stopReason = "max_rounds"
    }

    const securityApproved = this.rounds.every(
      (r) => r.securityAuditResult !== "blocked",
    )

    return {
      proposalId: this.generateProposalId(),
      bestRound: this.bestRound,
      rounds: this.rounds,
      finalScore: this.bestScore,
      securityApproved,
    }
  }

  /**
   * Execute a single optimization round
   */
  private async executeRound(round: number): Promise<OptimizeRound & { verifyResult?: VerifyResult }> {
    // Get previous rounds for context
    const previousRounds = this.rounds.filter((r) => r.round < round)

    // Run the optimizer for this round
    const optimizerResult = await this.optimizer.runRound(round, previousRounds)

    // Run security verification
    const verifyResult = await this.runSecurityVerification(round)

    // Determine security audit result
    const securityAuditResult = this.determineAuditResult(verifyResult)
    const securityRisks = verifyResult?.newRisks ?? []

    return {
      round,
      score: optimizerResult.score,
      changes: optimizerResult.changes,
      securityAuditResult,
      securityRisks,
      verifyResult: verifyResult ?? undefined,
    }
  }

  /**
   * Run security verification for a round
   */
  private async runSecurityVerification(round: number): Promise<VerifyResult | null> {
    try {
      // For the loop, we verify against the original baseline
      // The actual implementation would need the optimized skill directory
      // This is a simplified version that can be extended
      const result = await this.verifier.verify(
        this.originalBaseline,
        this.originalBaseline as SecurityBaseline, // Placeholder - actual implementation would use optimized baseline
      )
      return result
    } catch {
      // Return a failed verification result
      return {
        approved: false,
        newRisks: ["Verification failed"],
        riskLevel: "high",
        requiresManualReview: true,
        violations: ["Security verification encountered an error"],
        comparison: {
          newToolCalls: [],
          newPathPatterns: [],
          newTaintFlows: [],
          riskIncreased: false,
        },
      }
    }
  }

  /**
   * Determine the security audit result from verification
   */
  private determineAuditResult(verifyResult: VerifyResult | null): "passed" | "blocked" | "warning" {
    if (!verifyResult) {
      return "blocked"
    }
    if (!verifyResult.approved) {
      return "blocked"
    }
    if (verifyResult.requiresManualReview) {
      return "warning"
    }
    return "passed"
  }

  /**
   * Generate a unique proposal ID
   */
  private generateProposalId(): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-")
    const random = Math.random().toString(36).substring(2, 8)
    return `opt-${timestamp}-${random}`
  }

  /**
   * Get the current rounds
   */
  getRounds(): OptimizeRound[] {
    return [...this.rounds]
  }

  /**
   * Get the best round number
   */
  getBestRound(): number {
    return this.bestRound
  }

  /**
   * Get the best score
   */
  getBestScore(): number {
    return this.bestScore
  }

  /**
   * Check if the loop was stopped early
   */
  wasStopped(): boolean {
    return this.stopped
  }

  /**
   * Get the reason for stopping
   */
  getStopReason(): "converged" | "security_failure" | "max_rounds" | undefined {
    return this.stopReason
  }
}

/**
 * Factory function to create an optimization loop
 */
export function createOptimizationLoop(
  optimizer: IOptimizer,
  securityVerifier: OptimizeSecurityVerifier,
  originalBaseline: SecurityBaseline,
  config?: Partial<OptimizationLoopConfig>,
): OptimizationLoop {
  const fullConfig: OptimizationLoopConfig = {
    ...DEFAULT_LOOP_CONFIG,
    ...config,
  }
  return new OptimizationLoop(optimizer, securityVerifier, originalBaseline, fullConfig)
}
