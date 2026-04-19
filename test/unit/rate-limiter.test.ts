import { describe, it, expect, beforeEach, afterEach } from "bun:test"
import { RateLimiter, createRateLimiter, getDefaultRateLimiter, setDefaultRateLimiter } from "../../src/policy/rate-limiter.ts"
import { createRateLimitHook, createCombinedSecurityHook } from "../../src/hooks/security-check.ts"
import { PolicyRegistry } from "../../src/policy/registry.ts"
import { UnaryGatePolicy } from "../../src/policy/unary-gate.ts"
import { TaintTracker } from "../../src/taint/tracker.ts"
import { PathRegistry } from "../../src/taint/path-registry.ts"
import type { BeforeToolContext } from "../../src/types/hooks.ts"

describe("RateLimiter", () => {
  let limiter: RateLimiter

  afterEach(() => {
    if (limiter) {
      limiter.destroy()
    }
  })

  describe("basic functionality", () => {
    it("should create a rate limiter with default config", () => {
      limiter = new RateLimiter({ max_calls_per_window: 100, window_seconds: 60 })
      const config = limiter.getConfig()
      expect(config.max_calls_per_window).toBe(100)
      expect(config.window_seconds).toBe(60)
    })

    it("should allow calls within the limit", () => {
      limiter = new RateLimiter({ max_calls_per_window: 5, window_seconds: 60 })
      
      for (let i = 0; i < 5; i++) {
        const result = limiter.checkLimit("test-key")
        expect(result.allowed).toBe(true)
        expect(result.remaining).toBe(4 - i)
      }
    })

    it("should block calls exceeding the limit", () => {
      limiter = new RateLimiter({ max_calls_per_window: 3, window_seconds: 60 })
      
      // 前3次调用应该被允许
      for (let i = 0; i < 3; i++) {
        const result = limiter.checkLimit("test-key")
        expect(result.allowed).toBe(true)
      }
      
      // 第4次调用应该被阻止
      const result = limiter.checkLimit("test-key")
      expect(result.allowed).toBe(false)
      expect(result.remaining).toBe(0)
      expect(result.retryAfter).toBeDefined()
    })

    it("should track different keys independently", () => {
      limiter = new RateLimiter({ max_calls_per_window: 2, window_seconds: 60 })
      
      // 对 key1 进行2次调用
      expect(limiter.checkLimit("key1").allowed).toBe(true)
      expect(limiter.checkLimit("key1").allowed).toBe(true)
      expect(limiter.checkLimit("key1").allowed).toBe(false)
      
      // key2 应该仍然可以调用
      expect(limiter.checkLimit("key2").allowed).toBe(true)
      expect(limiter.checkLimit("key2").allowed).toBe(true)
      expect(limiter.checkLimit("key2").allowed).toBe(false)
    })
  })

  describe("sliding window", () => {
    it("should allow calls after window expires", async () => {
      limiter = new RateLimiter({ max_calls_per_window: 2, window_seconds: 1 })
      
      // 用完配额
      expect(limiter.checkLimit("test-key").allowed).toBe(true)
      expect(limiter.checkLimit("test-key").allowed).toBe(true)
      expect(limiter.checkLimit("test-key").allowed).toBe(false)
      
      // 等待窗口过期
      await new Promise(resolve => setTimeout(resolve, 1100))
      
      // 应该可以再次调用
      const result = limiter.checkLimit("test-key")
      expect(result.allowed).toBe(true)
    })

    it("should correctly calculate reset time", () => {
      limiter = new RateLimiter({ max_calls_per_window: 5, window_seconds: 60 })
      
      const beforeCall = Date.now()
      const result = limiter.checkLimit("test-key")
      const afterCall = Date.now()
      
      expect(result.allowed).toBe(true)
      expect(result.resetTime).toBeGreaterThanOrEqual(beforeCall + 60000)
      expect(result.resetTime).toBeLessThanOrEqual(afterCall + 60000)
    })
  })

  describe("stats and reset", () => {
    it("should return correct stats", () => {
      limiter = new RateLimiter({ max_calls_per_window: 10, window_seconds: 60 })
      
      limiter.checkLimit("test-key")
      limiter.checkLimit("test-key")
      limiter.checkLimit("test-key")
      
      const stats = limiter.getStats("test-key")
      expect(stats.count).toBe(3)
      expect(stats.remaining).toBe(7)
    })

    it("should reset a specific key", () => {
      limiter = new RateLimiter({ max_calls_per_window: 2, window_seconds: 60 })
      
      limiter.checkLimit("test-key")
      limiter.checkLimit("test-key")
      expect(limiter.checkLimit("test-key").allowed).toBe(false)
      
      limiter.reset("test-key")
      
      const stats = limiter.getStats("test-key")
      expect(stats.count).toBe(0)
      expect(limiter.checkLimit("test-key").allowed).toBe(true)
    })

    it("should reset all keys", () => {
      limiter = new RateLimiter({ max_calls_per_window: 1, window_seconds: 60 })
      
      limiter.checkLimit("key1")
      limiter.checkLimit("key2")
      
      expect(limiter.checkLimit("key1").allowed).toBe(false)
      expect(limiter.checkLimit("key2").allowed).toBe(false)
      
      limiter.resetAll()
      
      expect(limiter.checkLimit("key1").allowed).toBe(true)
      expect(limiter.checkLimit("key2").allowed).toBe(true)
    })
  })

  describe("config update", () => {
    it("should update config", () => {
      limiter = new RateLimiter({ max_calls_per_window: 10, window_seconds: 60 })
      
      limiter.updateConfig({ max_calls_per_window: 5 })
      
      const config = limiter.getConfig()
      expect(config.max_calls_per_window).toBe(5)
      expect(config.window_seconds).toBe(60)
    })
  })

  describe("tryCall helper", () => {
    it("should return boolean for tryCall", () => {
      limiter = new RateLimiter({ max_calls_per_window: 2, window_seconds: 60 })
      
      expect(limiter.tryCall("test-key")).toBe(true)
      expect(limiter.tryCall("test-key")).toBe(true)
      expect(limiter.tryCall("test-key")).toBe(false)
    })
  })
})

describe("createRateLimiter factory", () => {
  it("should create a rate limiter instance", () => {
    const limiter = createRateLimiter({ max_calls_per_window: 50, window_seconds: 30 })
    const config = limiter.getConfig()
    
    expect(config.max_calls_per_window).toBe(50)
    expect(config.window_seconds).toBe(30)
    
    limiter.destroy()
  })
})

describe("default rate limiter", () => {
  afterEach(() => {
    setDefaultRateLimiter(null)
  })

  it("should set and get default rate limiter", () => {
    const limiter = new RateLimiter({ max_calls_per_window: 100, window_seconds: 60 })
    setDefaultRateLimiter(limiter)
    
    expect(getDefaultRateLimiter()).toBe(limiter)
    
    limiter.destroy()
  })

  it("should return null when no default is set", () => {
    expect(getDefaultRateLimiter()).toBeNull()
  })
})

describe("createRateLimitHook", () => {
  let policyRegistry: PolicyRegistry
  let taintTracker: TaintTracker
  let limiter: RateLimiter

  beforeEach(() => {
    policyRegistry = new PolicyRegistry()
    policyRegistry.register(
      { name: "unary-gate", class_path: "policy/unary-gate", enabled: true, order: 0 },
      new UnaryGatePolicy({ unary_gate: { fail_closed_on_missing_instruction: false } }),
    )

    const pathRegistry = new PathRegistry()
    taintTracker = new TaintTracker(pathRegistry)
    limiter = new RateLimiter({ max_calls_per_window: 3, window_seconds: 60 })
  })

  afterEach(() => {
    limiter.destroy()
  })

  it("should allow tool calls within rate limit", async () => {
    const hook = createRateLimitHook({
      policyRegistry,
      taintTracker,
      traceId: "test-trace",
      rateLimiter: limiter,
    })

    const ctx: BeforeToolContext = {
      toolCall: {
        tool_name: "read",
        tool_call_id: "call-1",
        arguments: { path: "/tmp/test.txt" },
      },
      workDir: "/tmp",
      iteration: 1,
    }

    for (let i = 0; i < 3; i++) {
      const result = await hook(ctx)
      expect(result.action).toBe("passthrough")
    }
  })

  it("should block tool calls exceeding rate limit", async () => {
    const hook = createRateLimitHook({
      policyRegistry,
      taintTracker,
      traceId: "test-trace",
      rateLimiter: limiter,
    })

    const ctx: BeforeToolContext = {
      toolCall: {
        tool_name: "read",
        tool_call_id: "call-1",
        arguments: { path: "/tmp/test.txt" },
      },
      workDir: "/tmp",
      iteration: 1,
    }

    // 用完配额
    for (let i = 0; i < 3; i++) {
      await hook(ctx)
    }

    // 第4次应该被阻止
    const result = await hook(ctx)
    expect(result.action).toBe("block")
    if (result.action === "block") {
      expect(result.reason).toContain("Rate limit exceeded")
    }
  })

  it("should pass through when no rate limiter is configured", async () => {
    const hook = createRateLimitHook({
      policyRegistry,
      taintTracker,
      traceId: "test-trace",
    })

    const ctx: BeforeToolContext = {
      toolCall: {
        tool_name: "read",
        tool_call_id: "call-1",
        arguments: { path: "/tmp/test.txt" },
      },
      workDir: "/tmp",
      iteration: 1,
    }

    // 即使多次调用也应该通过
    for (let i = 0; i < 10; i++) {
      const result = await hook(ctx)
      expect(result.action).toBe("passthrough")
    }
  })

  it("should use custom key generator", async () => {
    const customLimiter = new RateLimiter({ max_calls_per_window: 1, window_seconds: 60 })
    
    const hook = createRateLimitHook({
      policyRegistry,
      taintTracker,
      traceId: "test-trace",
      rateLimiter: customLimiter,
      rateLimitKeyGenerator: (ctx) => `custom:${ctx.workDir}`,
    })

    const ctx1: BeforeToolContext = {
      toolCall: {
        tool_name: "read",
        tool_call_id: "call-1",
        arguments: { path: "/tmp/test.txt" },
      },
      workDir: "/tmp",
      iteration: 1,
    }

    const ctx2: BeforeToolContext = {
      toolCall: {
        tool_name: "write",
        tool_call_id: "call-2",
        arguments: { path: "/tmp/output.txt" },
      },
      workDir: "/tmp",
      iteration: 1,
    }

    // 第一次调用应该通过
    const result1 = await hook(ctx1)
    expect(result1.action).toBe("passthrough")

    // 第二次调用（不同的工具，相同的工作目录）应该被阻止
    const result2 = await hook(ctx2)
    expect(result2.action).toBe("block")

    customLimiter.destroy()
  })
})

describe("createCombinedSecurityHook", () => {
  let policyRegistry: PolicyRegistry
  let taintTracker: TaintTracker
  let limiter: RateLimiter

  beforeEach(() => {
    policyRegistry = new PolicyRegistry()
    policyRegistry.register(
      { name: "unary-gate", class_path: "policy/unary-gate", enabled: true, order: 0 },
      new UnaryGatePolicy({ unary_gate: { fail_closed_on_missing_instruction: false } }),
    )

    const pathRegistry = new PathRegistry()
    taintTracker = new TaintTracker(pathRegistry)
    limiter = new RateLimiter({ max_calls_per_window: 2, window_seconds: 60 })
  })

  afterEach(() => {
    limiter.destroy()
  })

  it("should check rate limit first, then policy", async () => {
    const hook = createCombinedSecurityHook({
      policyRegistry,
      taintTracker,
      traceId: "test-trace",
      rateLimiter: limiter,
    })

    const ctx: BeforeToolContext = {
      toolCall: {
        tool_name: "read",
        tool_call_id: "call-1",
        arguments: { path: "/tmp/test.txt" },
      },
      workDir: "/tmp",
      iteration: 1,
    }

    // 前两次应该通过
    expect((await hook(ctx)).action).toBe("passthrough")
    expect((await hook(ctx)).action).toBe("passthrough")

    // 第三次应该被速率限制阻止
    const result = await hook(ctx)
    expect(result.action).toBe("block")
    if (result.action === "block") {
      expect(result.reason).toContain("Rate limit exceeded")
    }
  })

  it("should allow tool calls when both rate limit and policy pass", async () => {
    const hook = createCombinedSecurityHook({
      policyRegistry,
      taintTracker,
      traceId: "test-trace",
      rateLimiter: limiter,
    })

    const ctx: BeforeToolContext = {
      toolCall: {
        tool_name: "read",
        tool_call_id: "call-1",
        arguments: { path: "/tmp/test.txt" },
      },
      workDir: "/tmp",
      iteration: 1,
    }

    const result = await hook(ctx)
    expect(result.action).toBe("passthrough")
  })
})
