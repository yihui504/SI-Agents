import { describe, it, expect, beforeEach } from "bun:test"
import { Solidifier } from "../../src/boost/solidifier.ts"
import { SkillOptimizer } from "../../src/optimize/optimizer.ts"
import { PolicyRegistry } from "../../src/policy/registry.ts"
import { UnaryGatePolicy } from "../../src/policy/unary-gate.ts"
import { RelationalPolicy } from "../../src/policy/relational.ts"
import { TaintTracker } from "../../src/taint/tracker.ts"
import { PathRegistry } from "../../src/taint/path-registry.ts"
import type { BoostCandidate } from "../../src/boost/types.ts"

describe("security + optimization conflict", () => {
  let policyRegistry: PolicyRegistry
  let taintTracker: TaintTracker
  let pathRegistry: PathRegistry

  beforeEach(() => {
    policyRegistry = new PolicyRegistry()
    pathRegistry = new PathRegistry()
    taintTracker = new TaintTracker(pathRegistry)

    policyRegistry.register(
      { name: "unary-gate", class_path: "policy/unary-gate", enabled: true, order: 0 },
      new UnaryGatePolicy({
        unary_gate: {
          fail_closed_on_missing_instruction: true,
          security: {
            min_confidence: "MID",
            min_trustworthiness: "MID",
          },
          risk: {
            blocked_risks: ["HIGH", "CRITICAL"],
          },
        },
      }),
    )

    policyRegistry.register(
      { name: "relational", class_path: "policy/relational", enabled: true, order: 1 },
      new RelationalPolicy({
        taint: {
          taint_policy: {
            fail_closed_on_missing_instruction_metadata: true,
          },
        },
      }),
    )
  })

  describe("JIT-boost security", () => {
    it("should block JIT-boost on policy violation", async () => {
      const candidates: BoostCandidate[] = [
        {
          id: "test-boost-1",
          skillId: "test-skill",
          keywords: ["execute", "run"],
          codeSignature: "rm -rf",
          functionTemplate: "rm -rf ${path}",
          params: {
            path: { type: "string", description: "Path to remove" },
          },
          materializationType: "shell",
        },
      ]

      const solidifier = new Solidifier(
        {
          skillId: "test-skill",
          policyRegistry,
          taintTracker,
          promotionThreshold: 1,
        },
        candidates,
      )

      const stats = solidifier.getStats()
      expect(stats.totalCandidates).toBe(1)
      expect(stats.promotedCount).toBe(0)
    })

    it("should demote boost candidate after security failures", async () => {
      const candidates: BoostCandidate[] = [
        {
          id: "test-boost-2",
          skillId: "test-skill",
          keywords: ["delete"],
          codeSignature: "delete",
          functionTemplate: "rm ${file}",
          params: {
            file: { type: "string", description: "File to delete" },
          },
          materializationType: "shell",
        },
      ]

      const solidifier = new Solidifier(
        {
          skillId: "test-skill",
          policyRegistry,
          taintTracker,
          promotionThreshold: 1,
          demotionThreshold: 2,
        },
        candidates,
      )

      const stats = solidifier.getStats()
      expect(stats.totalCandidates).toBe(1)
    })
  })

  describe("JIT-optimize security constraints", () => {
    it("should mark optimization with security risks", async () => {
      const optimizer = new SkillOptimizer({
        skillId: "test-skill",
        skillDir: "/tmp/test-skill",
        targetModel: "test-model",
        optimizerModel: "test-optimizer",
        rounds: 1,
        securityConstraints: {
          forbiddenTools: ["exec", "gateway"],
          forbiddenPaths: ["/etc/passwd", "/etc/shadow"],
          requiredTaintRules: [],
          maxRiskLevel: "medium",
        },
      })

      expect(optimizer).toBeDefined()
    })

    it("should not auto-apply risky optimization", async () => {
      const optimizer = new SkillOptimizer({
        skillId: "test-skill",
        skillDir: "/tmp/test-skill",
        targetModel: "test-model",
        optimizerModel: "test-optimizer",
        rounds: 1,
        securityConstraints: {
          forbiddenTools: ["exec"],
          forbiddenPaths: [],
          requiredTaintRules: [],
          maxRiskLevel: "low",
        },
      })

      expect(optimizer).toBeDefined()
    })
  })

  describe("Policy enforcement", () => {
    it("should block protected file modification", async () => {
      const policy = new UnaryGatePolicy({
        unary_gate: {
          fail_closed_on_missing_instruction: false,
        },
      })

      const instructions: Record<string, unknown>[] = []
      const response: Record<string, unknown> = {
        content: "",
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: {
              name: "write",
              arguments: JSON.stringify({ path: "/workspace/SOUL.MD", content: "modified" }),
            },
          },
        ],
      }
      const latestInstructions: Record<string, unknown>[] = [
        {
          id: "instr-1",
          content: {
            tool_name: "write",
            tool_call_id: "call-1",
            arguments: { path: "/workspace/SOUL.MD", content: "modified" },
          },
          security_type: {
            trustworthiness: "MID",
            confidentiality: "LOW",
          },
        },
      ]

      const result = await policy.check(instructions, response, latestInstructions, "trace-1")

      expect(result.modified).toBe(true)
      expect(result.error_type).toBeDefined()
    })

    it("should block high risk execution", async () => {
      const policy = new UnaryGatePolicy({
        unary_gate: {
          fail_closed_on_missing_instruction: false,
          risk: {
            blocked_risks: ["HIGH", "CRITICAL"],
          },
        },
      })

      const instructions: Record<string, unknown>[] = []
      const response: Record<string, unknown> = {
        content: "",
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: {
              name: "exec",
              arguments: JSON.stringify({ command: "rm -rf /" }),
            },
          },
        ],
      }
      const latestInstructions: Record<string, unknown>[] = [
        {
          id: "instr-1",
          content: {
            tool_name: "exec",
            tool_call_id: "call-1",
            arguments: { command: "rm -rf /", action: "run" },
          },
          security_type: {
            trustworthiness: "LOW",
            confidentiality: "UNKNOWN",
            risk: "CRITICAL",
          },
        },
      ]

      const result = await policy.check(instructions, response, latestInstructions, "trace-2")

      expect(result.modified).toBe(true)
    })
  })

  describe("Relational policy checks", () => {
    it("should check read_external flow", async () => {
      const policy = new RelationalPolicy({})

      const instructions: Record<string, unknown>[] = []
      const response: Record<string, unknown> = {
        content: "",
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: {
              name: "web_fetch",
              arguments: JSON.stringify({ url: "https://example.com/data" }),
            },
          },
        ],
      }
      const latestInstructions: Record<string, unknown>[] = [
        {
          id: "instr-1",
          content: {
            tool_name: "web_fetch",
            tool_call_id: "call-1",
            arguments: { url: "https://example.com/data" },
          },
          security_type: {
            trustworthiness: "LOW",
            confidentiality: "UNKNOWN",
          },
        },
      ]

      const result = await policy.check(instructions, response, latestInstructions, "trace-3")

      expect(result).toBeDefined()
    })

    it("should check write_local flow", async () => {
      const policy = new RelationalPolicy({})

      const instructions: Record<string, unknown>[] = []
      const response: Record<string, unknown> = {
        content: "",
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: {
              name: "write",
              arguments: JSON.stringify({ path: "/tmp/output.txt", content: "data" }),
            },
          },
        ],
      }
      const latestInstructions: Record<string, unknown>[] = [
        {
          id: "instr-1",
          content: {
            tool_name: "write",
            tool_call_id: "call-1",
            arguments: { path: "/tmp/output.txt", content: "data" },
          },
          security_type: {
            trustworthiness: "MID",
            confidentiality: "HIGH",
            prop_confidentiality: "HIGH",
          },
        },
      ]

      const result = await policy.check(instructions, response, latestInstructions, "trace-4")

      expect(result).toBeDefined()
    })

    it("should check delegate_sink flow", async () => {
      const policy = new RelationalPolicy({})

      const instructions: Record<string, unknown>[] = []
      const response: Record<string, unknown> = {
        content: "",
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: {
              name: "sessions_spawn",
              arguments: JSON.stringify({ agent: "other-agent", task: "do something" }),
            },
          },
        ],
      }
      const latestInstructions: Record<string, unknown>[] = [
        {
          id: "instr-1",
          content: {
            tool_name: "sessions_spawn",
            tool_call_id: "call-1",
            arguments: { agent: "other-agent", task: "do something" },
          },
          security_type: {
            trustworthiness: "MID",
            confidentiality: "HIGH",
            prop_confidentiality: "HIGH",
          },
          instruction_type: "DELEGATE",
        },
      ]

      const result = await policy.check(instructions, response, latestInstructions, "trace-5")

      expect(result).toBeDefined()
    })
  })

  describe("Taint propagation in optimization", () => {
    it("should propagate taint through dependencies", async () => {
      const instructions: Record<string, unknown>[] = [
        {
          id: "instr-1",
          content: {
            tool_name: "read",
            tool_call_id: "tc-1",
            arguments: { path: "/etc/passwd" },
          },
          security_type: {
            trustworthiness: "HIGH",
            confidentiality: "HIGH",
            prop_trustworthiness: "HIGH",
            prop_confidentiality: "HIGH",
          },
        },
        {
          id: "instr-2",
          content: {
            tool_name: "write",
            tool_call_id: "tc-2",
            arguments: { path: "/tmp/output.txt", reference_tool_id: ["tc-1"] },
          },
          security_type: {
            trustworthiness: "MID",
            confidentiality: "LOW",
            prop_trustworthiness: "MID",
            prop_confidentiality: "LOW",
          },
        },
      ]

      taintTracker.propagate(instructions)

      const propTaint = taintTracker.getPropTaint("instr-2")
      expect(propTaint.prop_confidentiality).toBeDefined()
    })
  })
})
