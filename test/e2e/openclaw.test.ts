import { describe, it, expect, beforeAll, afterAll } from "bun:test"
import { ProxyServer } from "../../src/proxy/server.ts"
import { OpenClawAdapter } from "../../src/adapters/openclaw.ts"
import { PolicyRegistry } from "../../src/policy/registry.ts"
import { UnaryGatePolicy } from "../../src/policy/unary-gate.ts"
import { RelationalPolicy } from "../../src/policy/relational.ts"
import { TaintTracker } from "../../src/taint/tracker.ts"
import { PathRegistry } from "../../src/taint/path-registry.ts"
import { MockLLMServer } from "../helpers/mock-llm.ts"
import { createTestWorkDir, cleanupTestWorkDir } from "../helpers/test-skill.ts"

describe("openclaw e2e", () => {
  let proxy: ProxyServer
  let mockLLM: MockLLMServer
  let workDir: string
  let policyRegistry: PolicyRegistry
  let taintTracker: TaintTracker

  beforeAll(async () => {
    mockLLM = new MockLLMServer(4101)
    await mockLLM.start()

    workDir = await createTestWorkDir("openclaw-test")

    policyRegistry = new PolicyRegistry()
    policyRegistry.register(
      { name: "unary-gate", class_path: "policy/unary-gate", enabled: true, order: 0 },
      new UnaryGatePolicy({ unary_gate: { fail_closed_on_missing_instruction: false } }),
    )
    policyRegistry.register(
      { name: "relational", class_path: "policy/relational", enabled: true, order: 1 },
      new RelationalPolicy({}),
    )

    const pathRegistry = new PathRegistry()
    taintTracker = new TaintTracker(pathRegistry)

    proxy = new ProxyServer({
      port: 4102,
      host: "localhost",
      modelRoutes: [
        { name: "test-model", api_base: mockLLM.getUrl(), api_key: "test-key" },
      ],
      defaultModel: "test-model",
      policyRegistry,
      taintTracker,
      observeOnly: false,
      securityDir: workDir,
    })
    proxy.start()
  })

  afterAll(async () => {
    proxy.stop()
    await mockLLM.stop()
    await cleanupTestWorkDir(workDir)
  })

  it("should generate proxy config", async () => {
    const adapter = new OpenClawAdapter({ model: "test-model" })
    const config = adapter.generateProxyConfig("http://localhost:4102", 4102)

    expect(config.provider).toBeDefined()
    expect(config.baseUrl).toBe("http://localhost:4102")
    expect(config.models).toBeDefined()
  })

  it("should generate full proxy config with multiple models", async () => {
    const adapter = new OpenClawAdapter({ model: "test-model" })
    const config = adapter.generateFullProxyConfig({
      proxyUrl: "http://localhost:4102",
      proxyPort: 4102,
      models: [
        { id: "model-1", name: "Model One" },
        { id: "model-2", name: "Model Two" },
      ],
      defaultModel: "model-1",
    })

    expect(config).toContain("si-agents")
    expect(config).toContain("model-1")
    expect(config).toContain("model-2")
  })

  it("should generate environment variables", async () => {
    const adapter = new OpenClawAdapter({ model: "test-model" })
    const envVars = adapter.generateEnvVars("http://localhost:4102", 4102)

    expect(envVars).toBeDefined()
    expect(envVars["OPENAI_API_BASE"]).toBe("http://localhost:4102/v1")
  })

  it("should parse tool calls correctly", async () => {
    const adapter = new OpenClawAdapter({ model: "test-model" })

    const toolCalls = [
      { id: "call-1", name: "read_file", arguments: '{"path": "test.txt"}' },
      { id: "call-2", name: "write_file", arguments: '{"path": "output.txt", "content": "hello"}' },
    ]

    const parsed = adapter.parseToolCalls(toolCalls)

    expect(parsed.length).toBe(2)
    expect(parsed[0]!.name).toBe("read_file")
    expect(parsed[0]!.args.path).toBe("test.txt")
    expect(parsed[1]!.name).toBe("write_file")
  })

  it("should get tool aliases", async () => {
    const adapter = new OpenClawAdapter({ model: "test-model" })
    const aliases = adapter.getToolAliases()

    expect(aliases).toBeDefined()
    expect(typeof aliases).toBe("object")
  })

  it("should get security attributes for tools", async () => {
    const adapter = new OpenClawAdapter({ model: "test-model" })

    const readAttrs = adapter.getSecurityAttributes("read_file", { path: "/etc/passwd" })
    expect(readAttrs).toBeDefined()

    const writeAttrs = adapter.getSecurityAttributes("write_file", { path: "/tmp/test.txt" })
    expect(writeAttrs).toBeDefined()
  })

  it("should create and manage sessions", async () => {
    const adapter = new OpenClawAdapter({ model: "test-model" })

    const sessionId = await adapter.createSession({
      skillDir: workDir,
      taskPrompt: "Test task",
      workDir,
    })

    expect(sessionId).toBeDefined()
    expect(typeof sessionId).toBe("string")

    const session = adapter.getSession(sessionId)
    expect(session).toBeDefined()
    expect(session!.id).toBe(sessionId)

    await adapter.endSession(sessionId)
  })

  it("should record tool calls in sessions", async () => {
    const adapter = new OpenClawAdapter({ model: "test-model" })

    const sessionId = await adapter.createSession({
      skillDir: workDir,
      taskPrompt: "Test task",
      workDir,
    })

    const toolCalls = [
      { id: "call-1", name: "read_file", arguments: '{"path": "test.txt"}' },
    ]

    const parsed = adapter.recordToolCalls(sessionId, toolCalls)
    expect(parsed.length).toBe(1)

    adapter.recordToolResult(sessionId, "call-1", "File content here")

    await adapter.endSession(sessionId)
  })

  it("should track active sessions", async () => {
    const adapter = new OpenClawAdapter({ model: "test-model" })

    const sessionId1 = await adapter.createSession({
      skillDir: workDir,
      taskPrompt: "Test task 1",
      workDir,
    })

    const sessionId2 = await adapter.createSession({
      skillDir: workDir,
      taskPrompt: "Test task 2",
      workDir,
    })

    const activeSessions = adapter.getActiveSessions()
    expect(activeSessions.length).toBeGreaterThanOrEqual(2)

    await adapter.endSession(sessionId1)
    await adapter.endSession(sessionId2)

    adapter.clearCompletedSessions()
  })

  it("should handle optimize callback", async () => {
    let optimizeCalled = false
    const adapter = new OpenClawAdapter({
      model: "test-model",
      optimizeEnabled: true,
      optimizeCallback: async () => {
        optimizeCalled = true
      },
    })

    adapter.setOptimizeEnabled(true)
    expect(adapter).toBeDefined()

    adapter.setOptimizeCallback(async () => {
      optimizeCalled = true
    })
    expect(adapter).toBeDefined()
  })
})
