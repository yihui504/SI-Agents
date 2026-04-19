import { describe, it, expect, beforeAll, afterAll } from "bun:test"
import { BareAgentAdapter } from "../../src/adapters/bare-agent.ts"
import type { LLMProvider, LLMResponse, CompletionParams, LLMToolResult } from "../../src/adapters/types.ts"
import { MockLLMServer } from "../helpers/mock-llm.ts"
import { createTestSkill, cleanupTestSkill, createTestWorkDir, cleanupTestWorkDir, SAMPLE_SKILL_CONTENT } from "../helpers/test-skill.ts"

class MockLLMProvider implements LLMProvider {
  readonly name = "mock"
  private server: MockLLMServer

  constructor(server: MockLLMServer) {
    this.server = server
  }

  async complete(params: CompletionParams): Promise<LLMResponse> {
    const response = await fetch(`${this.server.getUrl()}/v1/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "test-model",
        messages: params.messages,
        stream: false,
      }),
    })
    const data = await response.json() as Record<string, unknown>
    return this.parseResponse(data)
  }

  async completeWithToolResults(
    params: CompletionParams,
    toolResults: LLMToolResult[],
    _prevResponse: LLMResponse,
  ): Promise<LLMResponse> {
    const toolResultContent = toolResults.map((tr) => `Tool result: ${tr.content}`).join("\n")
    const messages = [...params.messages, { role: "user" as const, content: toolResultContent }]
    
    const response = await fetch(`${this.server.getUrl()}/v1/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "test-model",
        messages,
        stream: false,
      }),
    })
    const data = await response.json() as Record<string, unknown>
    return this.parseResponse(data)
  }

  private parseResponse(data: Record<string, unknown>): LLMResponse {
    const choices = data.choices as Array<Record<string, unknown>>
    const choice = choices?.[0]
    const message = choice?.message as Record<string, unknown> | undefined
    const toolCalls = (message?.tool_calls as Array<Record<string, unknown>> | undefined)?.map((tc) => {
      const fn = tc.function as Record<string, unknown>
      return {
        id: tc.id as string,
        name: fn.name as string,
        arguments: JSON.parse(fn.arguments as string) as Record<string, unknown>,
      }
    }) ?? []

    return {
      text: (message?.content as string) ?? "",
      toolCalls,
      tokens: { input: 100, output: 50 },
      durationMs: 100,
      stopReason: toolCalls.length > 0 ? "tool_use" : "end_turn",
    }
  }
}

describe("bare-agent e2e", () => {
  let mockLLM: MockLLMServer
  let skillDir: string
  let workDir: string

  beforeAll(async () => {
    mockLLM = new MockLLMServer(4100)
    await mockLLM.start()
    skillDir = await createTestSkill("test-skill", SAMPLE_SKILL_CONTENT)
    workDir = await createTestWorkDir("bare-agent-test")
  })

  afterAll(async () => {
    await mockLLM.stop()
    await cleanupTestSkill(skillDir)
    await cleanupTestWorkDir(workDir)
  })

  it("should complete simple task", async () => {
    const adapter = new BareAgentAdapter(
      (config) => new MockLLMProvider(mockLLM),
    )
    await adapter.setup({ model: "test-model", baseUrl: mockLLM.getUrl() })

    mockLLM.setResponses([
      { content: "Task completed successfully" },
    ])

    const result = await adapter.run({
      prompt: "Complete the test task",
      workDir,
      skillContent: SAMPLE_SKILL_CONTENT,
    })

    expect(result.runStatus).toBe("ok")
    expect(result.text).toContain("Task completed successfully")
  })

  it("should handle tool calls", async () => {
    const adapter = new BareAgentAdapter(
      (config) => new MockLLMProvider(mockLLM),
    )
    await adapter.setup({ model: "test-model", baseUrl: mockLLM.getUrl() })

    mockLLM.setResponses([
      { toolCalls: [{ name: "read_file", arguments: { path: "test.txt" } }] },
      { content: "File content processed" },
    ])

    const result = await adapter.run({
      prompt: "Read and process test.txt",
      workDir,
      skillContent: SAMPLE_SKILL_CONTENT,
    })

    expect(result.runStatus).toBe("ok")
    expect(result.steps.length).toBeGreaterThan(1)
  })

  it("should handle multiple tool calls in sequence", async () => {
    const adapter = new BareAgentAdapter(
      (config) => new MockLLMProvider(mockLLM),
    )
    await adapter.setup({ model: "test-model", baseUrl: mockLLM.getUrl() })

    mockLLM.setResponses([
      { toolCalls: [{ name: "read_file", arguments: { path: "input.txt" } }] },
      { toolCalls: [{ name: "write_file", arguments: { path: "output.txt", content: "processed" } }] },
      { content: "Files processed successfully" },
    ])

    const result = await adapter.run({
      prompt: "Read input.txt and write to output.txt",
      workDir,
      skillContent: SAMPLE_SKILL_CONTENT,
    })

    expect(result.runStatus).toBe("ok")
    expect(result.steps.length).toBeGreaterThan(2)
  })

  it("should handle exec tool calls", async () => {
    const adapter = new BareAgentAdapter(
      (config) => new MockLLMProvider(mockLLM),
    )
    await adapter.setup({ model: "test-model", baseUrl: mockLLM.getUrl() })

    mockLLM.setResponses([
      { toolCalls: [{ name: "exec", arguments: { command: "echo hello" } }] },
      { content: "Command executed successfully" },
    ])

    const result = await adapter.run({
      prompt: "Run echo command",
      workDir,
      skillContent: SAMPLE_SKILL_CONTENT,
    })

    expect(result.runStatus).toBe("ok")
  })

  it("should handle list_directory tool calls", async () => {
    const adapter = new BareAgentAdapter(
      (config) => new MockLLMProvider(mockLLM),
    )
    await adapter.setup({ model: "test-model", baseUrl: mockLLM.getUrl() })

    mockLLM.setResponses([
      { toolCalls: [{ name: "list_directory", arguments: { path: "." } }] },
      { content: "Directory listed successfully" },
    ])

    const result = await adapter.run({
      prompt: "List current directory",
      workDir,
      skillContent: SAMPLE_SKILL_CONTENT,
    })

    expect(result.runStatus).toBe("ok")
  })

  it("should track token usage", async () => {
    const adapter = new BareAgentAdapter(
      (config) => new MockLLMProvider(mockLLM),
    )
    await adapter.setup({ model: "test-model", baseUrl: mockLLM.getUrl() })

    mockLLM.setResponses([
      { content: "Task completed" },
    ])

    const result = await adapter.run({
      prompt: "Complete task",
      workDir,
      skillContent: SAMPLE_SKILL_CONTENT,
    })

    expect(result.tokens.input).toBeGreaterThanOrEqual(0)
    expect(result.tokens.output).toBeGreaterThanOrEqual(0)
  })

  it("should track duration", async () => {
    const adapter = new BareAgentAdapter(
      (config) => new MockLLMProvider(mockLLM),
    )
    await adapter.setup({ model: "test-model", baseUrl: mockLLM.getUrl() })

    mockLLM.setResponses([
      { content: "Task completed" },
    ])

    const result = await adapter.run({
      prompt: "Complete task",
      workDir,
      skillContent: SAMPLE_SKILL_CONTENT,
    })

    expect(result.durationMs).toBeGreaterThanOrEqual(0)
  })

  it("should handle skill injection mode", async () => {
    const adapter = new BareAgentAdapter(
      (config) => new MockLLMProvider(mockLLM),
    )
    await adapter.setup({ model: "test-model", baseUrl: mockLLM.getUrl() })

    mockLLM.setResponses([
      { content: "Skill loaded and task completed" },
    ])

    const result = await adapter.run({
      prompt: "Complete task using skill",
      workDir,
      skillContent: SAMPLE_SKILL_CONTENT,
      skillMode: "inject",
    })

    expect(result.runStatus).toBe("ok")
    expect(result.skillLoaded).toBe(true)
  })
})
