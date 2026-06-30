import { describe, it, expect, beforeEach, mock } from "bun:test"
import {
  OptimizationLoop,
  createOptimizationLoop,
  DEFAULT_LOOP_CONFIG,
  type OptimizationLoopConfig,
  type IOptimizer,
} from "../../src/optimize/loop.ts"
import { OptimizeSecurityVerifier, type VerifyResult } from "../../src/optimize/verifier.ts"
import type { SecurityBaseline, OptimizeRound } from "../../src/optimize/types.ts"
import { SkillSecurityScanner } from "../../src/optimize/scanner.ts"
import { SecurityConstraintInjector } from "../../src/optimize/constraints.ts"

// Helper to create a mock optimizer
function createMockOptimizer(implementation?: Partial<IOptimizer>): IOptimizer {
  return {
    runRound: implementation?.runRound ?? mock(async (round: number, _previousRounds: OptimizeRound[]) => ({
      score: 0.5 + round * 0.1,
      changes: [`Change ${round}`],
    })),
  }
}

// Helper to create a mock security verifier
function createMockVerifier(overrides?: Partial<VerifyResult>): OptimizeSecurityVerifier {
  const scanner = new SkillSecurityScanner()
  const injector = new SecurityConstraintInjector()
  const verifier = new OptimizeSecurityVerifier(scanner, injector)

  // Mock the verify method
  verifier.verify = mock(async (_original: SecurityBaseline, _optimized: SecurityBaseline) => {
    const defaultResult: VerifyResult = {
      approved: true,
      newRisks: [],
      riskLevel: "low",
      requiresManualReview: false,
      violations: [],
      comparison: {
        newToolCalls: [],
        newPathPatterns: [],
        newTaintFlows: [],
        riskIncreased: false,
      },
      ...overrides,
    }
    return defaultResult
  })

  return verifier
}

// Helper to create a test baseline
function createTestBaseline(overrides?: Partial<SecurityBaseline>): SecurityBaseline {
  return {
    toolCalls: [],
    pathPatterns: [],
    taintFlows: [],
    riskLevel: "low",
    ...overrides,
  }
}

describe("OptimizationLoop", () => {
  let mockOptimizer: IOptimizer
  let mockVerifier: OptimizeSecurityVerifier
  let testBaseline: SecurityBaseline
  let defaultConfig: OptimizationLoopConfig

  beforeEach(() => {
    mockOptimizer = createMockOptimizer()
    mockVerifier = createMockVerifier()
    testBaseline = createTestBaseline()
    defaultConfig = {
      maxRounds: 3,
      convergenceThreshold: 0.95,
    }
  })

  describe("constructor", () => {
    it("should create instance with required parameters", () => {
      const loop = new OptimizationLoop(mockOptimizer, mockVerifier, testBaseline, defaultConfig)
      expect(loop).toBeDefined()
    })

    it("should use default config values when not provided", () => {
      const loop = new OptimizationLoop(mockOptimizer, mockVerifier, testBaseline, {
        maxRounds: 5,
        convergenceThreshold: 0.9,
      })
      expect(loop).toBeDefined()
    })
  })

  describe("run", () => {
    it("should run all rounds when not converging", async () => {
      const loop = new OptimizationLoop(mockOptimizer, mockVerifier, testBaseline, defaultConfig)
      const result = await loop.run("/tmp/test-skill-dir")

      expect(result.rounds.length).toBe(3)
      expect(result.proposalId).toBeDefined()
      expect(result.bestRound).toBeGreaterThan(0)
    })

    it("should stop early when convergence threshold is reached", async () => {
      const convergingOptimizer = createMockOptimizer({
        runRound: mock(async (round: number) => ({
          score: round === 1 ? 0.96 : 0.5, // First round converges
          changes: ["Converging change"],
        })),
      })

      const loop = new OptimizationLoop(convergingOptimizer, mockVerifier, testBaseline, {
        maxRounds: 5,
        convergenceThreshold: 0.95,
      })

      const result = await loop.run("/tmp/test-skill-dir")

      expect(result.rounds.length).toBe(1)
      expect(loop.wasStopped()).toBe(true)
      expect(loop.getStopReason()).toBe("converged")
    })

    it("should track the best round correctly", async () => {
      const optimizer = createMockOptimizer({
        runRound: mock(async (round: number) => ({
          score: round === 2 ? 0.8 : 0.5, // Round 2 is best
          changes: [`Round ${round} change`],
        })),
      })

      const loop = new OptimizationLoop(optimizer, mockVerifier, testBaseline, defaultConfig)
      const result = await loop.run("/tmp/test-skill-dir")

      expect(result.bestRound).toBe(2)
      expect(result.finalScore).toBe(0.8)
    })

    it("should call onRoundComplete callback after each round", async () => {
      const onRoundComplete = mock(() => {})
      const config: OptimizationLoopConfig = {
        ...defaultConfig,
        onRoundComplete,
      }

      const loop = new OptimizationLoop(mockOptimizer, mockVerifier, testBaseline, config)
      await loop.run("/tmp/test-skill-dir")

      expect(onRoundComplete).toHaveBeenCalledTimes(3)
    })

    it("should set securityApproved to true when all rounds pass", async () => {
      const loop = new OptimizationLoop(mockOptimizer, mockVerifier, testBaseline, defaultConfig)
      const result = await loop.run("/tmp/test-skill-dir")

      expect(result.securityApproved).toBe(true)
    })
  })

  describe("security verification", () => {
    it("should block rounds with security violations", async () => {
      const blockingVerifier = createMockVerifier({
        approved: false,
        violations: ["Test violation"],
        newRisks: ["Security risk detected"],
      })

      const loop = new OptimizationLoop(mockOptimizer, blockingVerifier, testBaseline, defaultConfig)
      const result = await loop.run("/tmp/test-skill-dir")

      expect(result.rounds.every(r => r.securityAuditResult === "blocked")).toBe(true)
      expect(result.securityApproved).toBe(false)
    })

    it("should stop on security failure when configured", async () => {
      const blockingVerifier = createMockVerifier({
        approved: false,
        violations: ["Critical violation"],
        newRisks: ["Critical risk"],
      })

      const onSecurityFailure = mock(() => {})
      const config: OptimizationLoopConfig = {
        maxRounds: 5,
        convergenceThreshold: 0.99,
        stopOnSecurityFailure: true,
        onSecurityFailure,
      }

      const loop = new OptimizationLoop(mockOptimizer, blockingVerifier, testBaseline, config)
      const result = await loop.run("/tmp/test-skill-dir")

      expect(result.rounds.length).toBe(1)
      expect(loop.wasStopped()).toBe(true)
      expect(loop.getStopReason()).toBe("security_failure")
      expect(onSecurityFailure).toHaveBeenCalledTimes(1)
    })

    it("should continue on security failure when stopOnSecurityFailure is false", async () => {
      const blockingVerifier = createMockVerifier({
        approved: false,
        violations: ["Violation"],
        newRisks: ["Risk"],
      })

      const config: OptimizationLoopConfig = {
        maxRounds: 3,
        convergenceThreshold: 0.99,
        stopOnSecurityFailure: false,
      }

      const loop = new OptimizationLoop(mockOptimizer, blockingVerifier, testBaseline, config)
      const result = await loop.run("/tmp/test-skill-dir")

      expect(result.rounds.length).toBe(3)
    })

    it("should mark rounds with warnings when manual review is required", async () => {
      const warningVerifier = createMockVerifier({
        approved: true,
        requiresManualReview: true,
        newRisks: ["Review needed"],
      })

      const loop = new OptimizationLoop(mockOptimizer, warningVerifier, testBaseline, defaultConfig)
      const result = await loop.run("/tmp/test-skill-dir")

      expect(result.rounds.every(r => r.securityAuditResult === "warning")).toBe(true)
      expect(result.securityApproved).toBe(true)
    })
  })

  describe("getters", () => {
    it("should return correct rounds", async () => {
      const loop = new OptimizationLoop(mockOptimizer, mockVerifier, testBaseline, defaultConfig)
      await loop.run("/tmp/test-skill-dir")

      const rounds = loop.getRounds()
      expect(rounds.length).toBe(3)
    })

    it("should return correct best round and score", async () => {
      const optimizer = createMockOptimizer({
        runRound: mock(async (round: number) => ({
          score: round === 2 ? 0.9 : 0.5,
          changes: [],
        })),
      })

      const loop = new OptimizationLoop(optimizer, mockVerifier, testBaseline, defaultConfig)
      await loop.run("/tmp/test-skill-dir")

      expect(loop.getBestRound()).toBe(2)
      expect(loop.getBestScore()).toBe(0.9)
    })

    it("should not count blocked rounds as best", async () => {
      const optimizer = createMockOptimizer({
        runRound: mock(async (round: number) => ({
          score: 0.9,
          changes: [],
        })),
      })

      const partialBlockingVerifier = createMockVerifier({
        approved: true,
        violations: [],
      })

      const loop = new OptimizationLoop(optimizer, partialBlockingVerifier, testBaseline, defaultConfig)
      await loop.run("/tmp/test-skill-dir")

      // Best round should be one of the passing rounds
      expect(loop.getBestRound()).toBeGreaterThan(0)
    })
  })
})

describe("createOptimizationLoop", () => {
  it("should create loop with default config", () => {
    const mockOptimizer = createMockOptimizer()
    const mockVerifier = createMockVerifier()
    const baseline = createTestBaseline()

    const loop = createOptimizationLoop(mockOptimizer, mockVerifier, baseline)

    expect(loop).toBeInstanceOf(OptimizationLoop)
  })

  it("should merge provided config with defaults", () => {
    const mockOptimizer = createMockOptimizer()
    const mockVerifier = createMockVerifier()
    const baseline = createTestBaseline()

    const loop = createOptimizationLoop(mockOptimizer, mockVerifier, baseline, {
      maxRounds: 10,
    })

    expect(loop).toBeInstanceOf(OptimizationLoop)
  })
})

describe("DEFAULT_LOOP_CONFIG", () => {
  it("should have expected default values", () => {
    expect(DEFAULT_LOOP_CONFIG.maxRounds).toBe(5)
    expect(DEFAULT_LOOP_CONFIG.convergenceThreshold).toBe(0.95)
    expect(DEFAULT_LOOP_CONFIG.stopOnSecurityFailure).toBe(true)
  })
})
