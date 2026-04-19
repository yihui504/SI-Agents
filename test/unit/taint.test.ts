import { describe, it, expect, beforeEach } from "bun:test"
import { PathRegistry } from "../../src/taint/path-registry.ts"
import { computePropTaint, computePropTaintForInstruction } from "../../src/taint/propagation.ts"
import { TaintTracker } from "../../src/taint/tracker.ts"
import { ToolAliasMapper } from "../../src/taint/tool-aliases.ts"

describe("PathRegistry", () => {
  let registry: PathRegistry

  describe("trustworthiness classification", () => {
    beforeEach(() => {
      registry = new PathRegistry("linux")
    })

    it("should classify external URLs as LOW trustworthiness", () => {
      const result = registry.classifyTrustworthiness(["https://example.com/data"])
      expect(result).toBe("LOW")
    })

    it("should classify tmp paths as LOW trustworthiness", () => {
      const result = registry.classifyTrustworthiness(["/tmp/file.txt"])
      expect(result).toBe("LOW")
    })

    it("should classify system binaries as HIGH trustworthiness", () => {
      const result = registry.classifyTrustworthiness(["/usr/bin/ls"])
      expect(result).toBe("HIGH")
    })

    it("should classify downloads as LOW trustworthiness", () => {
      const result = registry.classifyTrustworthiness(["/home/user/Downloads/file.zip"])
      expect(result).toBe("LOW")
    })

    it("should return UNKNOWN for unclassifiable paths", () => {
      const result = registry.classifyTrustworthiness(["/home/user/projects/app.js"])
      expect(result).toBe("UNKNOWN")
    })

    it("should return worst trustworthiness for multiple paths", () => {
      const result = registry.classifyTrustworthiness(["/usr/bin/ls", "/tmp/file.txt"])
      expect(result).toBe("LOW")
    })
  })

  describe("confidentiality classification", () => {
    beforeEach(() => {
      registry = new PathRegistry("linux")
    })

    it("should classify /etc/shadow as HIGH confidentiality", () => {
      const result = registry.classifyConfidentiality(["/etc/shadow"])
      expect(result).toBe("HIGH")
    })

    it("should classify SSH keys as HIGH confidentiality", () => {
      const result = registry.classifyConfidentiality(["/home/user/.ssh/id_rsa"])
      expect(result).toBe("HIGH")
    })

    it("should classify AWS credentials as HIGH confidentiality", () => {
      const result = registry.classifyConfidentiality(["/home/user/.aws/credentials"])
      expect(result).toBe("HIGH")
    })

    it("should classify .env files as HIGH confidentiality", () => {
      const result = registry.classifyConfidentiality(["/app/.env"])
      expect(result).toBe("HIGH")
    })

    it("should classify certificate files as HIGH confidentiality", () => {
      const result = registry.classifyConfidentiality(["/etc/ssl/private/server.key"])
      expect(result).toBe("HIGH")
    })

    it("should classify .pem files as HIGH confidentiality", () => {
      const result = registry.classifyConfidentiality(["/home/user/cert.pem"])
      expect(result).toBe("HIGH")
    })

    it("should return highest confidentiality for multiple paths", () => {
      const result = registry.classifyConfidentiality(["/tmp/file.txt", "/etc/shadow"])
      expect(result).toBe("HIGH")
    })
  })

  describe("platform-specific rules", () => {
    it("should handle Windows paths", () => {
      const winRegistry = new PathRegistry("windows")
      
      expect(winRegistry.classifyTrustworthiness(["C:/Windows/System32/kernel32.dll"])).toBe("HIGH")
      expect(winRegistry.classifyConfidentiality(["C:/Users/user/.ssh/id_rsa"])).toBe("HIGH")
    })

    it("should handle macOS paths", () => {
      const darwinRegistry = new PathRegistry("darwin")
      
      expect(darwinRegistry.classifyTrustworthiness(["/System/Library/CoreServices"])).toBe("HIGH")
      expect(darwinRegistry.classifyConfidentiality(["/Users/user/.ssh/id_rsa"])).toBe("HIGH")
    })
  })

  describe("custom rules", () => {
    it("should load custom rules", () => {
      registry = new PathRegistry("linux")
      registry.loadRules([
        { pattern: "/custom/secret/*", trustworthiness: "LOW", confidentiality: "HIGH" },
      ])

      expect(registry.classifyTrustworthiness(["/custom/secret/data"])).toBe("LOW")
      expect(registry.classifyConfidentiality(["/custom/secret/data"])).toBe("HIGH")
    })

    it("should load rules from data", () => {
      registry = new PathRegistry("linux")
      registry.loadFromData({
        LOW: ["/custom/low/*"],
        HIGH: ["/custom/high/*"],
      })

      expect(registry.classifyTrustworthiness(["/custom/low/file.txt"])).toBe("LOW")
      expect(registry.classifyConfidentiality(["/custom/high/file.txt"])).toBe("HIGH")
    })
  })
})

describe("computePropTaint", () => {
  it("should propagate taint through dependencies", () => {
    const instructions: Record<string, unknown>[] = [
      {
        id: "instr-1",
        content: {
          tool_name: "read",
          tool_call_id: "tc-1",
          arguments: { path: "/etc/shadow" },
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

    computePropTaint(instructions)

    const sec2 = instructions[1]!.security_type as Record<string, unknown>
    expect(sec2.prop_confidentiality).toBe("HIGH")
  })

  it("should handle multiple references", () => {
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
          confidentiality: "MID",
          prop_trustworthiness: "HIGH",
          prop_confidentiality: "MID",
        },
      },
      {
        id: "instr-2",
        content: {
          tool_name: "read",
          tool_call_id: "tc-2",
          arguments: { path: "/etc/shadow" },
        },
        security_type: {
          trustworthiness: "HIGH",
          confidentiality: "HIGH",
          prop_trustworthiness: "HIGH",
          prop_confidentiality: "HIGH",
        },
      },
      {
        id: "instr-3",
        content: {
          tool_name: "write",
          tool_call_id: "tc-3",
          arguments: { path: "/tmp/out.txt", reference_tool_id: ["tc-1", "tc-2"] },
        },
        security_type: {
          trustworthiness: "MID",
          confidentiality: "LOW",
          prop_trustworthiness: "MID",
          prop_confidentiality: "LOW",
        },
      },
    ]

    computePropTaint(instructions)

    const sec3 = instructions[2]!.security_type as Record<string, unknown>
    expect(sec3.prop_confidentiality).toBe("HIGH")
  })

  it("should handle instructions without tool calls", () => {
    const instructions: Record<string, unknown>[] = [
      {
        id: "instr-1",
        content: { text: "Some text content" },
        security_type: {
          trustworthiness: "MID",
          confidentiality: "LOW",
        },
      },
    ]

    computePropTaint(instructions)

    const sec = instructions[0]!.security_type as Record<string, unknown>
    expect(sec.prop_trustworthiness).toBe("MID")
    expect(sec.prop_confidentiality).toBe("LOW")
  })
})

describe("computePropTaintForInstruction", () => {
  it("should compute propagation for single instruction", () => {
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
          confidentiality: "MID",
        },
      },
    ]

    const result = computePropTaintForInstruction(instructions, instructions[0]!)

    expect(result.prop_trustworthiness).toBe("HIGH")
    expect(result.prop_confidentiality).toBe("MID")
  })

  it("should handle missing security_type", () => {
    const instructions: Record<string, unknown>[] = [
      {
        id: "instr-1",
        content: { text: "content" },
      },
    ]

    const result = computePropTaintForInstruction(instructions, instructions[0]!)

    expect(result.prop_trustworthiness).toBe("UNKNOWN")
    expect(result.prop_confidentiality).toBe("UNKNOWN")
  })
})

describe("TaintTracker", () => {
  let tracker: TaintTracker
  let pathRegistry: PathRegistry

  beforeEach(() => {
    pathRegistry = new PathRegistry("linux")
    tracker = new TaintTracker(pathRegistry)
  })

  describe("setBaseTaint", () => {
    it("should set taint for input tools", () => {
      const instruction: Record<string, unknown> = {
        id: "instr-1",
        content: {
          tool_name: "read",
          tool_call_id: "tc-1",
          arguments: { path: "/etc/passwd" },
        },
      }

      tracker.setBaseTaint(instruction, "read", { path: "/etc/passwd" })

      const sec = instruction.security_type as Record<string, unknown>
      expect(sec.trustworthiness).toBe("HIGH")
      expect(sec.confidentiality).toBe("HIGH")
    })

    it("should set taint for output tools", () => {
      const instruction: Record<string, unknown> = {
        id: "instr-1",
        content: {
          tool_name: "write",
          tool_call_id: "tc-1",
          arguments: { path: "/tmp/output.txt" },
        },
      }

      tracker.setBaseTaint(instruction, "write", { path: "/tmp/output.txt" })

      const sec = instruction.security_type as Record<string, unknown>
      expect(sec.trustworthiness).toBe("LOW")
    })

    it("should set taint for web_fetch tool", () => {
      const instruction: Record<string, unknown> = {
        id: "instr-1",
        content: {
          tool_name: "web_fetch",
          tool_call_id: "tc-1",
          arguments: { url: "https://example.com" },
        },
      }

      tracker.setBaseTaint(instruction, "web_fetch", { url: "https://example.com" })

      const sec = instruction.security_type as Record<string, unknown>
      expect(sec.trustworthiness).toBe("LOW")
    })
  })

  describe("propagate", () => {
    it("should propagate taint across instructions", () => {
      const instructions: Record<string, unknown>[] = [
        {
          id: "instr-1",
          content: {
            tool_name: "read",
            tool_call_id: "tc-1",
            arguments: { path: "/etc/shadow" },
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
            arguments: { path: "/tmp/out.txt", reference_tool_id: ["tc-1"] },
          },
          security_type: {
            trustworthiness: "MID",
            confidentiality: "LOW",
            prop_trustworthiness: "MID",
            prop_confidentiality: "LOW",
          },
        },
      ]

      tracker.propagate(instructions)

      const propTaint = tracker.getPropTaint("instr-2")
      expect(propTaint.prop_confidentiality).toBe("HIGH")
    })
  })

  describe("checkTaintPolicy", () => {
    it("should allow when trustworthiness >= confidentiality", () => {
      const securityType = {
        trustworthiness: "HIGH",
        confidentiality: "MID",
        prop_confidentiality: "MID",
      }

      const result = tracker.checkTaintPolicy("read", { path: "/etc/passwd" }, securityType)

      expect(result.allowed).toBe(true)
    })

    it("should block when trustworthiness < confidentiality", () => {
      const securityType = {
        trustworthiness: "LOW",
        confidentiality: "HIGH",
        prop_confidentiality: "HIGH",
      }

      const result = tracker.checkTaintPolicy("read", { path: "/etc/shadow" }, securityType)

      expect(result.allowed).toBe(false)
      expect(result.reason).toBeDefined()
    })

    it("should allow for non-input/output tools", () => {
      const securityType = {
        trustworthiness: "LOW",
        confidentiality: "HIGH",
      }

      const result = tracker.checkTaintPolicy("unknown_tool", {}, securityType)

      expect(result.allowed).toBe(true)
    })
  })
})

describe("ToolAliasMapper", () => {
  let mapper: ToolAliasMapper

  beforeEach(() => {
    mapper = new ToolAliasMapper()
  })

  it("should canonicalize tool names", () => {
    expect(mapper.canonicalize("read_file")).toBe("read")
    expect(mapper.canonicalize("write_file")).toBe("write")
    expect(mapper.canonicalize("execute_command")).toBe("exec")
  })

  it("should return original name for unknown aliases", () => {
    expect(mapper.canonicalize("custom_tool")).toBe("custom_tool")
  })
})
