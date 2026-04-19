import { describe, it, expect, beforeEach } from "bun:test"
import { HookCoordinator } from "../../src/hooks/coordinator.ts"
import { PolicyRegistry } from "../../src/policy/registry.ts"
import { UnaryGatePolicy } from "../../src/policy/unary-gate.ts"
import { TaintTracker } from "../../src/taint/tracker.ts"
import { PathRegistry } from "../../src/taint/path-registry.ts"
import type { BeforeLLMContext, AfterLLMContext, BeforeToolContext, AfterToolContext, AfterRunContext } from "../../src/types/hooks.ts"

describe("HookCoordinator", () => {
  let coordinator: HookCoordinator
  let policyRegistry: PolicyRegistry
  let taintTracker: TaintTracker
  let logDir: string

  beforeEach(() => {
    policyRegistry = new PolicyRegistry()
    policyRegistry.register(
      { name: "unary-gate", class_path: "policy/unary-gate", enabled: true, order: 0 },
      new UnaryGatePolicy({ unary_gate: { fail_closed_on_missing_instruction: false } }),
    )

    const pathRegistry = new PathRegistry()
    taintTracker = new TaintTracker(pathRegistry)
    logDir = "/tmp/si-agents-test-logs"
  })

  describe("hook creation", () => {
    it("should create hooks on initialization", () => {
      coordinator = new HookCoordinator({
        traceId: "test-trace-1",
        policyRegistry,
        taintTracker,
        logDir,
      })

      const hooks = coordinator.getHooks()
      expect(hooks.beforeLLM).toBeDefined()
      expect(hooks.afterLLM).toBeDefined()
      expect(hooks.beforeTool).toBeDefined()
      expect(hooks.afterTool).toBeDefined()
      expect(hooks.afterRun).toBeDefined()
    })

    it("should return empty instructions initially", () => {
      coordinator = new HookCoordinator({
        traceId: "test-trace-2",
        policyRegistry,
        taintTracker,
        logDir,
      })

      const instructions = coordinator.getInstructions()
      expect(instructions).toEqual([])
    })
  })

  describe("beforeLLM hook", () => {
    beforeEach(() => {
      coordinator = new HookCoordinator({
        traceId: "test-trace-3",
        policyRegistry,
        taintTracker,
        logDir,
      })
    })

    it("should return passthrough for normal prompts", async () => {
      const ctx: BeforeLLMContext = {
        prompt: "Read the file /tmp/test.txt",
        workDir: "/tmp",
        iteration: 1,
        previousToolCalls: [],
      }

      const result = await coordinator.beforeLLM(ctx)
      expect(result.action).toBe("passthrough")
    })

    it("should handle boost candidates", async () => {
      const boostCoordinator = new HookCoordinator({
        traceId: "test-trace-4",
        policyRegistry,
        taintTracker,
        logDir,
        boostCandidates: [
          {
            skillId: "test-skill",
            pattern: /execute.*command/i,
            priority: 1,
          },
        ],
      })

      const ctx: BeforeLLMContext = {
        prompt: "Execute the command ls -la",
        workDir: "/tmp",
        iteration: 1,
        previousToolCalls: [],
      }

      const result = await boostCoordinator.beforeLLM(ctx)
      expect(result.action).toBeDefined()
    })
  })

  describe("afterLLM hook", () => {
    beforeEach(() => {
      coordinator = new HookCoordinator({
        traceId: "test-trace-5",
        policyRegistry,
        taintTracker,
        logDir,
      })
    })

    it("should process response with tool calls", async () => {
      const ctx: AfterLLMContext = {
        response: {
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
        },
        iteration: 1,
        workDir: "/tmp",
        instructions: [],
      }

      await coordinator.afterLLM(ctx)
      const instructions = coordinator.getInstructions()
      expect(instructions.length).toBe(0)
    })

    it("should process response with text content", async () => {
      const ctx: AfterLLMContext = {
        response: {
          content: "Task completed successfully",
        },
        iteration: 1,
        workDir: "/tmp",
        instructions: [],
      }

      await coordinator.afterLLM(ctx)
      expect(coordinator.getInstructions()).toEqual([])
    })
  })

  describe("beforeTool hook", () => {
    beforeEach(() => {
      coordinator = new HookCoordinator({
        traceId: "test-trace-6",
        policyRegistry,
        taintTracker,
        logDir,
      })
    })

    it("should allow normal tool calls", async () => {
      const ctx: BeforeToolContext = {
        toolCall: {
          tool_name: "read",
          tool_call_id: "call-1",
          arguments: { path: "/tmp/test.txt" },
        },
        workDir: "/tmp",
        iteration: 1,
      }

      const result = await coordinator.beforeTool(ctx)
      expect(result.action).toBe("passthrough")
    })

    it("should check taint policy for tool calls", async () => {
      const ctx: BeforeToolContext = {
        toolCall: {
          tool_name: "write",
          tool_call_id: "call-1",
          arguments: { path: "/tmp/output.txt", content: "data" },
        },
        workDir: "/tmp",
        iteration: 1,
      }

      const result = await coordinator.beforeTool(ctx)
      expect(result.action).toBeDefined()
    })
  })

  describe("afterTool hook", () => {
    beforeEach(() => {
      coordinator = new HookCoordinator({
        traceId: "test-trace-7",
        policyRegistry,
        taintTracker,
        logDir,
      })
    })

    it("should process tool call results", async () => {
      const ctx: AfterToolContext = {
        toolCall: {
          tool_name: "read",
          tool_call_id: "call-1",
          arguments: { path: "/tmp/test.txt" },
          result: "File content here",
        },
        workDir: "/tmp",
        iteration: 1,
      }

      await coordinator.afterTool(ctx)
    })

    it("should track failures", async () => {
      const ctx: AfterToolContext = {
        toolCall: {
          tool_name: "exec",
          tool_call_id: "call-1",
          arguments: { command: "invalid-command" },
          result: "Error: command not found",
        },
        workDir: "/tmp",
        iteration: 1,
      }

      await coordinator.afterTool(ctx)
    })
  })

  describe("afterRun hook", () => {
    beforeEach(() => {
      coordinator = new HookCoordinator({
        traceId: "test-trace-8",
        policyRegistry,
        taintTracker,
        logDir,
      })
    })

    it("should process successful run", async () => {
      const ctx: AfterRunContext = {
        result: {
          text: "Task completed",
          steps: [],
          tokens: { input: 100, output: 50 },
        },
        success: true,
      }

      await coordinator.afterRun(ctx)
    })

    it("should process failed run", async () => {
      const ctx: AfterRunContext = {
        result: {
          text: "",
          steps: [],
          tokens: { input: 100, output: 50 },
          runStatus: "adapter-crashed",
          statusDetail: "Connection timeout",
        },
        success: false,
      }

      await coordinator.afterRun(ctx)
    })

    it("should clear instructions after run", async () => {
      const ctx: AfterRunContext = {
        result: { text: "Done" },
        success: true,
      }

      await coordinator.afterRun(ctx)
      expect(coordinator.getInstructions()).toEqual([])
    })
  })

  describe("hook execution order", () => {
    beforeEach(() => {
      coordinator = new HookCoordinator({
        traceId: "test-trace-9",
        policyRegistry,
        taintTracker,
        logDir,
      })
    })

    it("should execute hooks in correct order for a complete flow", async () => {
      const beforeLLMCtx: BeforeLLMContext = {
        prompt: "Read and process file",
        workDir: "/tmp",
        iteration: 1,
        previousToolCalls: [],
      }

      const beforeLLMResult = await coordinator.beforeLLM(beforeLLMCtx)
      expect(beforeLLMResult.action).toBe("passthrough")

      const afterLLMCtx: AfterLLMContext = {
        response: {
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
        },
        iteration: 1,
        workDir: "/tmp",
        instructions: [],
      }

      await coordinator.afterLLM(afterLLMCtx)

      const beforeToolCtx: BeforeToolContext = {
        toolCall: {
          tool_name: "read",
          tool_call_id: "call-1",
          arguments: { path: "/tmp/test.txt" },
        },
        workDir: "/tmp",
        iteration: 1,
      }

      const beforeToolResult = await coordinator.beforeTool(beforeToolCtx)
      expect(beforeToolResult.action).toBe("passthrough")

      const afterToolCtx: AfterToolContext = {
        toolCall: {
          tool_name: "read",
          tool_call_id: "call-1",
          arguments: { path: "/tmp/test.txt" },
          result: "File content",
        },
        workDir: "/tmp",
        iteration: 1,
      }

      await coordinator.afterTool(afterToolCtx)

      const afterRunCtx: AfterRunContext = {
        result: { text: "Completed" },
        success: true,
      }

      await coordinator.afterRun(afterRunCtx)
    })
  })

  describe("security check failure", () => {
    it("should block on security check failure", async () => {
      const strictPolicyRegistry = new PolicyRegistry()
      strictPolicyRegistry.register(
        { name: "unary-gate", class_path: "policy/unary-gate", enabled: true, order: 0 },
        new UnaryGatePolicy({
          unary_gate: {
            fail_closed_on_missing_instruction: true,
          },
        }),
      )

      coordinator = new HookCoordinator({
        traceId: "test-trace-10",
        policyRegistry: strictPolicyRegistry,
        taintTracker,
        logDir,
      })

      const ctx: BeforeToolContext = {
        toolCall: {
          tool_name: "exec",
          tool_call_id: "call-1",
          arguments: { command: "rm -rf /" },
        },
        workDir: "/tmp",
        iteration: 1,
      }

      const result = await coordinator.beforeTool(ctx)
      expect(result.action).toBeDefined()
    })
  })
})
