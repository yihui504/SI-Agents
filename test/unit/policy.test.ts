import { describe, it, expect, beforeEach } from "bun:test"
import { UnaryGatePolicy } from "../../src/policy/unary-gate.ts"
import { RelationalPolicy } from "../../src/policy/relational.ts"
import { PolicyRegistry } from "../../src/policy/registry.ts"

describe("UnaryGatePolicy", () => {
  let policy: UnaryGatePolicy

  describe("UG-001: missing metadata", () => {
    beforeEach(() => {
      policy = new UnaryGatePolicy({
        unary_gate: {
          fail_closed_on_missing_instruction: true,
        },
      })
    })

    it("should block missing metadata when fail_closed_on_missing_instruction is true", async () => {
      const instructions: Record<string, unknown>[] = []
      const response: Record<string, unknown> = {
        content: "",
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: {
              name: "read",
              arguments: JSON.stringify({ path: "/tmp/test.txt" }),
            },
          },
        ],
      }
      const latestInstructions: Record<string, unknown>[] = []

      const result = await policy.check(instructions, response, latestInstructions, "trace-1")

      expect(result.modified).toBe(true)
      expect(result.error_type).toBeDefined()
    })

    it("should allow when metadata is present", async () => {
      const instructions: Record<string, unknown>[] = []
      const response: Record<string, unknown> = {
        content: "",
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: {
              name: "read",
              arguments: JSON.stringify({ path: "/tmp/test.txt" }),
            },
          },
        ],
      }
      const latestInstructions: Record<string, unknown>[] = [
        {
          id: "instr-1",
          content: {
            tool_name: "read",
            tool_call_id: "call-1",
            arguments: { path: "/tmp/test.txt" },
          },
          security_type: {
            trustworthiness: "MID",
            confidentiality: "LOW",
          },
        },
      ]

      const result = await policy.check(instructions, response, latestInstructions, "trace-2")

      expect(result.modified).toBe(false)
    })
  })

  describe("UG-010: argument string budget", () => {
    beforeEach(() => {
      policy = new UnaryGatePolicy({
        input_budget: {
          max_str_len: 1000,
        },
      })
    })

    it("should block when argument string length exceeds budget", async () => {
      const longContent = "x".repeat(2000)
      const instructions: Record<string, unknown>[] = []
      const response: Record<string, unknown> = {
        content: "",
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: {
              name: "write",
              arguments: JSON.stringify({ path: "/tmp/test.txt", content: longContent }),
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
            arguments: { path: "/tmp/test.txt", content: longContent },
          },
          security_type: {
            trustworthiness: "MID",
            confidentiality: "LOW",
          },
        },
      ]

      const result = await policy.check(instructions, response, latestInstructions, "trace-3")

      expect(result.modified).toBe(true)
    })
  })

  describe("UG-020: execution confidence too low", () => {
    beforeEach(() => {
      policy = new UnaryGatePolicy({
        unary_gate: {
          security: {
            min_confidence: "MID",
          },
        },
      })
    })

    it("should block when confidence is below required", async () => {
      const instructions: Record<string, unknown>[] = []
      const response: Record<string, unknown> = {
        content: "",
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: {
              name: "exec",
              arguments: JSON.stringify({ command: "ls" }),
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
            arguments: { command: "ls" },
          },
          security_type: {
            trustworthiness: "MID",
            confidentiality: "LOW",
            confidence: "LOW",
          },
        },
      ]

      const result = await policy.check(instructions, response, latestInstructions, "trace-4")

      expect(result.modified).toBe(true)
    })
  })

  describe("UG-021: execution trustworthiness too low", () => {
    beforeEach(() => {
      policy = new UnaryGatePolicy({
        unary_gate: {
          security: {
            min_trustworthiness: "HIGH",
          },
        },
      })
    })

    it("should block when trustworthiness is below required", async () => {
      const instructions: Record<string, unknown>[] = []
      const response: Record<string, unknown> = {
        content: "",
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: {
              name: "exec",
              arguments: JSON.stringify({ command: "ls" }),
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
            arguments: { command: "ls" },
          },
          security_type: {
            trustworthiness: "LOW",
            confidentiality: "LOW",
          },
        },
      ]

      const result = await policy.check(instructions, response, latestInstructions, "trace-5")

      expect(result.modified).toBe(true)
    })
  })

  describe("UG-030: high risk execution", () => {
    beforeEach(() => {
      policy = new UnaryGatePolicy({
        unary_gate: {
          risk: {
            blocked_risks: ["HIGH", "CRITICAL"],
          },
        },
      })
    })

    it("should block high risk execution", async () => {
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
            trustworthiness: "MID",
            confidentiality: "LOW",
            risk: "HIGH",
          },
        },
      ]

      const result = await policy.check(instructions, response, latestInstructions, "trace-6")

      expect(result.modified).toBe(true)
    })
  })

  describe("UG-031: approval required", () => {
    beforeEach(() => {
      policy = new UnaryGatePolicy({
        unary_gate: {
          risk: {
            block_approval_required: true,
          },
        },
      })
    })

    it("should block when approval_required is true", async () => {
      const instructions: Record<string, unknown>[] = []
      const response: Record<string, unknown> = {
        content: "",
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: {
              name: "exec",
              arguments: JSON.stringify({ command: "shutdown" }),
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
            arguments: { command: "shutdown" },
          },
          security_type: {
            trustworthiness: "MID",
            confidentiality: "LOW",
            custom: { approval_required: true },
          },
        },
      ]

      const result = await policy.check(instructions, response, latestInstructions, "trace-7")

      expect(result.modified).toBe(true)
    })
  })

  describe("UG-032: destructive and not reversible", () => {
    beforeEach(() => {
      policy = new UnaryGatePolicy({
        unary_gate: {
          risk: {
            block_destructive: true,
          },
        },
      })
    })

    it("should block destructive non-reversible operations", async () => {
      const instructions: Record<string, unknown>[] = []
      const response: Record<string, unknown> = {
        content: "",
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: {
              name: "exec",
              arguments: JSON.stringify({ command: "rm file.txt" }),
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
            arguments: { command: "rm file.txt" },
          },
          security_type: {
            trustworthiness: "MID",
            confidentiality: "LOW",
            reversible: false,
            custom: { destructive: true },
          },
        },
      ]

      const result = await policy.check(instructions, response, latestInstructions, "trace-8")

      expect(result.modified).toBe(true)
    })
  })

  describe("UG-040: blocked tags", () => {
    beforeEach(() => {
      policy = new UnaryGatePolicy({
        unary_gate: {
          tags: {
            blocked_tags: ["DESTRUCTIVE", "HIGH_RISK"],
          },
        },
      })
    })

    it("should block operations with blocked tags", async () => {
      const instructions: Record<string, unknown>[] = []
      const response: Record<string, unknown> = {
        content: "",
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: {
              name: "exec",
              arguments: JSON.stringify({ command: "format" }),
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
            arguments: { command: "format" },
          },
          security_type: {
            trustworthiness: "MID",
            confidentiality: "LOW",
            custom: { tags: ["DESTRUCTIVE"] },
          },
        },
      ]

      const result = await policy.check(instructions, response, latestInstructions, "trace-9")

      expect(result.modified).toBe(true)
    })
  })

  describe("UG-006: instruction type filter", () => {
    describe("deny.instruction_types blacklist", () => {
      beforeEach(() => {
        policy = new UnaryGatePolicy({
          policy: {
            deny: {
              instruction_types: ["DELEGATE", "EXEC"],
            },
          },
        })
      })

      it("should block instruction types in deny list", async () => {
        const instructions: Record<string, unknown>[] = []
        const response: Record<string, unknown> = {
          content: "",
          tool_calls: [
            {
              id: "call-1",
              type: "function",
              function: {
                name: "exec",
                arguments: JSON.stringify({ command: "ls" }),
              },
            },
          ],
        }
        const latestInstructions: Record<string, unknown>[] = [
          {
            id: "instr-1",
            instruction_type: "EXEC",
            content: {
              tool_name: "exec",
              tool_call_id: "call-1",
              arguments: { command: "ls" },
            },
            security_type: {
              trustworthiness: "MID",
              confidentiality: "LOW",
            },
          },
        ]

        const result = await policy.check(instructions, response, latestInstructions, "trace-ug006-1")

        expect(result.modified).toBe(true)
        expect(result.error_type).toBeDefined()
      })

      it("should allow instruction types not in deny list", async () => {
        const instructions: Record<string, unknown>[] = []
        const response: Record<string, unknown> = {
          content: "",
          tool_calls: [
            {
              id: "call-1",
              type: "function",
              function: {
                name: "read",
                arguments: JSON.stringify({ path: "/tmp/test.txt" }),
              },
            },
          ],
        }
        const latestInstructions: Record<string, unknown>[] = [
          {
            id: "instr-1",
            instruction_type: "READ",
            content: {
              tool_name: "read",
              tool_call_id: "call-1",
              arguments: { path: "/tmp/test.txt" },
            },
            security_type: {
              trustworthiness: "MID",
              confidentiality: "LOW",
            },
          },
        ]

        const result = await policy.check(instructions, response, latestInstructions, "trace-ug006-2")

        expect(result.modified).toBe(false)
      })
    })

    describe("allow.instruction_types whitelist", () => {
      beforeEach(() => {
        policy = new UnaryGatePolicy({
          policy: {
            allow: {
              instruction_types: ["READ", "WRITE"],
            },
          },
        })
      })

      it("should block instruction types not in allow list", async () => {
        const instructions: Record<string, unknown>[] = []
        const response: Record<string, unknown> = {
          content: "",
          tool_calls: [
            {
              id: "call-1",
              type: "function",
              function: {
                name: "exec",
                arguments: JSON.stringify({ command: "ls" }),
              },
            },
          ],
        }
        const latestInstructions: Record<string, unknown>[] = [
          {
            id: "instr-1",
            instruction_type: "EXEC",
            content: {
              tool_name: "exec",
              tool_call_id: "call-1",
              arguments: { command: "ls" },
            },
            security_type: {
              trustworthiness: "MID",
              confidentiality: "LOW",
            },
          },
        ]

        const result = await policy.check(instructions, response, latestInstructions, "trace-ug006-3")

        expect(result.modified).toBe(true)
        expect(result.error_type).toBeDefined()
      })

      it("should allow instruction types in allow list", async () => {
        const instructions: Record<string, unknown>[] = []
        const response: Record<string, unknown> = {
          content: "",
          tool_calls: [
            {
              id: "call-1",
              type: "function",
              function: {
                name: "read",
                arguments: JSON.stringify({ path: "/tmp/test.txt" }),
              },
            },
          ],
        }
        const latestInstructions: Record<string, unknown>[] = [
          {
            id: "instr-1",
            instruction_type: "READ",
            content: {
              tool_name: "read",
              tool_call_id: "call-1",
              arguments: { path: "/tmp/test.txt" },
            },
            security_type: {
              trustworthiness: "MID",
              confidentiality: "LOW",
            },
          },
        ]

        const result = await policy.check(instructions, response, latestInstructions, "trace-ug006-4")

        expect(result.modified).toBe(false)
      })
    })
  })

  describe("UG-060: protected file direct mutation", () => {
    beforeEach(() => {
      policy = new UnaryGatePolicy({})
    })

    it("should block direct write to SOUL.MD", async () => {
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

      const result = await policy.check(instructions, response, latestInstructions, "trace-10")

      expect(result.modified).toBe(true)
    })

    it("should block direct write to AGENTS.MD", async () => {
      const instructions: Record<string, unknown>[] = []
      const response: Record<string, unknown> = {
        content: "",
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: {
              name: "edit",
              arguments: JSON.stringify({ path: "/workspace/AGENTS.MD", content: "modified" }),
            },
          },
        ],
      }
      const latestInstructions: Record<string, unknown>[] = [
        {
          id: "instr-1",
          content: {
            tool_name: "edit",
            tool_call_id: "call-1",
            arguments: { path: "/workspace/AGENTS.MD", content: "modified" },
          },
          security_type: {
            trustworthiness: "MID",
            confidentiality: "LOW",
          },
        },
      ]

      const result = await policy.check(instructions, response, latestInstructions, "trace-11")

      expect(result.modified).toBe(true)
    })
  })

  describe("UG-061: protected file exec write target", () => {
    beforeEach(() => {
      policy = new UnaryGatePolicy({})
    })

    it("should block exec that writes to IDENTITY.MD", async () => {
      const instructions: Record<string, unknown>[] = []
      const response: Record<string, unknown> = {
        content: "",
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: {
              name: "exec",
              arguments: JSON.stringify({ command: "echo test > IDENTITY.MD" }),
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
            arguments: { command: "echo test > IDENTITY.MD" },
          },
          security_type: {
            trustworthiness: "MID",
            confidentiality: "LOW",
            custom: {
              exec_parse: {
                write_targets: ["/workspace/IDENTITY.MD"],
              },
            },
          },
        },
      ]

      const result = await policy.check(instructions, response, latestInstructions, "trace-12")

      expect(result.modified).toBe(true)
    })
  })
})

describe("RelationalPolicy", () => {
  let policy: RelationalPolicy

  beforeEach(() => {
    policy = new RelationalPolicy({})
  })

  describe("read_external flow", () => {
    it("should check web_fetch flow", async () => {
      const instructions: Record<string, unknown>[] = []
      const response: Record<string, unknown> = {
        content: "",
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: {
              name: "web_fetch",
              arguments: JSON.stringify({ url: "https://example.com" }),
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
            arguments: { url: "https://example.com" },
          },
          security_type: {
            trustworthiness: "LOW",
            confidentiality: "UNKNOWN",
          },
        },
      ]

      const result = await policy.check(instructions, response, latestInstructions, "trace-20")

      expect(result).toBeDefined()
    })
  })

  describe("write_local flow", () => {
    it("should check write flow", async () => {
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
            trustworthiness: "HIGH",
            confidentiality: "LOW",
            prop_confidentiality: "LOW",
          },
        },
      ]

      const result = await policy.check(instructions, response, latestInstructions, "trace-21")

      expect(result).toBeDefined()
    })
  })

  describe("exec_side_effect flow", () => {
    it("should check exec flow", async () => {
      const instructions: Record<string, unknown>[] = []
      const response: Record<string, unknown> = {
        content: "",
        tool_calls: [
          {
            id: "call-1",
            type: "function",
            function: {
              name: "exec",
              arguments: JSON.stringify({ command: "ls -la" }),
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
            arguments: { command: "ls -la" },
          },
          security_type: {
            trustworthiness: "MID",
            confidentiality: "LOW",
          },
        },
      ]

      const result = await policy.check(instructions, response, latestInstructions, "trace-22")

      expect(result).toBeDefined()
    })
  })
})

describe("PolicyRegistry", () => {
  let registry: PolicyRegistry

  beforeEach(() => {
    registry = new PolicyRegistry()
  })

  it("should register policies", () => {
    const policy = new UnaryGatePolicy({})
    registry.register(
      { name: "test-policy", class_path: "test", enabled: true, order: 0 },
      policy,
    )

    const policies = registry.getAllPolicies()
    expect(policies.length).toBe(1)
    expect(policies[0]).toBe(policy)
  })

  it("should get enabled policies", () => {
    const policy1 = new UnaryGatePolicy({})
    const policy2 = new RelationalPolicy({})

    registry.register(
      { name: "policy-1", class_path: "test", enabled: true, order: 0 },
      policy1,
    )
    registry.register(
      { name: "policy-2", class_path: "test", enabled: false, order: 1 },
      policy2,
    )

    const enabledPolicies = registry.getEnabledPolicies()
    expect(enabledPolicies.length).toBe(1)
    expect(enabledPolicies[0]).toBe(policy1)
  })

  it("should set enabled status", () => {
    const policy = new UnaryGatePolicy({})
    registry.register(
      { name: "test-policy", class_path: "test", enabled: true, order: 0 },
      policy,
    )

    registry.setEnabled("test-policy", false)

    const entry = registry.getEntry("test-policy")
    expect(entry!.enabled).toBe(false)
  })

  it("should get entries", () => {
    const policy = new UnaryGatePolicy({})
    registry.register(
      { name: "test-policy", class_path: "test", enabled: true, order: 0 },
      policy,
    )

    const entries = registry.getEntries()
    expect(entries.length).toBe(1)
    expect(entries[0]!.name).toBe("test-policy")
  })
})
