import { describe, it, expect, beforeEach } from "bun:test"
import { executePostCall } from "../../src/proxy/post-call.ts"
import type { ChatCompletionResponse, ProxyConfig } from "../../src/proxy/types.ts"
import { PolicyRegistry } from "../../src/policy/registry.ts"
import { UnaryGatePolicy } from "../../src/policy/unary-gate.ts"
import { TaintTracker } from "../../src/taint/tracker.ts"
import { PathRegistry } from "../../src/taint/path-registry.ts"

function createMockResponse(content: string, model: string = "test-model"): ChatCompletionResponse {
  return {
    id: "test-id",
    object: "chat.completion",
    created: Date.now(),
    model,
    choices: [
      {
        index: 0,
        message: {
          role: "assistant",
          content,
        },
        finish_reason: "stop",
      },
    ],
  }
}

function createMockConfig(outputBudget?: { max_chars?: number }): ProxyConfig {
  const policyRegistry = new PolicyRegistry()
  policyRegistry.register(
    { name: "unary-gate", class_path: "policy/unary-gate", enabled: true, order: 0 },
    new UnaryGatePolicy({}),
  )

  const pathRegistry = new PathRegistry()
  const taintTracker = new TaintTracker(pathRegistry)

  return {
    policyRegistry,
    taintTracker,
    modelRoutes: new Map(),
    observeOnly: false,
    securityDir: "/tmp/test-security",
    output_budget: outputBudget,
  }
}

describe("Output Budget", () => {
  let pendingConfirmations: Map<string, string>

  beforeEach(() => {
    pendingConfirmations = new Map()
  })

  describe("output_budget.max_chars", () => {
    it("should allow response within output budget", async () => {
      const config = createMockConfig({ max_chars: 1000 })
      const response = createMockResponse("This is a short response")

      const result = await executePostCall(
        response,
        "trace-1",
        config,
        [],
        pendingConfirmations
      )

      expect(result.modified).toBe(false)
      expect(result.policyBlocked).toBe(false)
    })

    it("should block response exceeding output budget", async () => {
      const config = createMockConfig({ max_chars: 100 })
      const longContent = "x".repeat(200)
      const response = createMockResponse(longContent)

      const result = await executePostCall(
        response,
        "trace-2",
        config,
        [],
        pendingConfirmations
      )

      expect(result.modified).toBe(true)
      expect(result.policyBlocked).toBe(true)
      expect(result.policyMessage).toContain("200")
      expect(result.policyMessage).toContain("100")
    })

    it("should truncate response content when exceeding budget", async () => {
      const config = createMockConfig({ max_chars: 50 })
      const longContent = "This is a very long response that exceeds the budget limit"
      const response = createMockResponse(longContent)

      const result = await executePostCall(
        response,
        "trace-3",
        config,
        [],
        pendingConfirmations
      )

      expect(result.modified).toBe(true)
      expect(result.policyBlocked).toBe(true)
      const message = result.response.choices[0]?.message.content || ""
      expect(message).toContain("输出长度超限")
    })

    it("should not apply output budget when max_chars is undefined", async () => {
      const config = createMockConfig({})
      const longContent = "x".repeat(10000)
      const response = createMockResponse(longContent)

      const result = await executePostCall(
        response,
        "trace-4",
        config,
        [],
        pendingConfirmations
      )

      expect(result.modified).toBe(false)
      expect(result.policyBlocked).toBe(false)
    })

    it("should not apply output budget when output_budget is undefined", async () => {
      const config = createMockConfig(undefined)
      const longContent = "x".repeat(10000)
      const response = createMockResponse(longContent)

      const result = await executePostCall(
        response,
        "trace-5",
        config,
        [],
        pendingConfirmations
      )

      expect(result.modified).toBe(false)
      expect(result.policyBlocked).toBe(false)
    })

    it("should handle response with tool calls", async () => {
      const config = createMockConfig({ max_chars: 100 })
      const response: ChatCompletionResponse = {
        id: "test-id",
        object: "chat.completion",
        created: Date.now(),
        model: "test-model",
        choices: [
          {
            index: 0,
            message: {
              role: "assistant",
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
            finish_reason: "tool_calls",
          },
        ],
      }

      const result = await executePostCall(
        response,
        "trace-6",
        config,
        [],
        pendingConfirmations
      )

      expect(result.modified).toBe(false)
    })
  })
})
