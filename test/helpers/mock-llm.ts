import { Hono } from "hono"
import { cors } from "hono/cors"

export interface MockLLMResponse {
  content?: string
  toolCalls?: Array<{ name: string; arguments: Record<string, unknown>; id?: string }>
}

export interface MockLLMCallLog {
  request: unknown
  response: unknown
}

export class MockLLMServer {
  private responses: MockLLMResponse[] = []
  private callLog: MockLLMCallLog[] = []
  private port: number
  private app: Hono
  private server: ReturnType<typeof Bun.serve> | null = null
  private responseIndex = 0

  constructor(port: number = 4100) {
    this.port = port
    this.app = new Hono()
    this.setupRoutes()
  }

  private setupRoutes(): void {
    this.app.use("*", cors())

    this.app.get("/v1/models", (c) => {
      return c.json({
        object: "list",
        data: [
          {
            id: "test-model",
            object: "model",
            created: Math.floor(Date.now() / 1000),
            owned_by: "test",
          },
        ],
      })
    })

    this.app.post("/v1/chat/completions", async (c) => {
      const request = await c.req.json()
      this.callLog.push({ request, response: null })

      const response = this.generateResponse(request)
      this.callLog[this.callLog.length - 1]!.response = response

      if (request.stream) {
        return this.handleStreamingResponse(c, response)
      }

      return c.json(response)
    })

    this.app.get("/health", (c) => {
      return c.json({ status: "ok", timestamp: new Date().toISOString() })
    })
  }

  private generateResponse(request: Record<string, unknown>): Record<string, unknown> {
    const mockResponse = this.responses[this.responseIndex] ?? { content: "Default mock response" }
    this.responseIndex = (this.responseIndex + 1) % Math.max(this.responses.length, 1)

    const messages = request.messages as Array<{ role: string; content: string }> | undefined
    const lastMessage = messages?.[messages.length - 1]

    const toolCalls = mockResponse.toolCalls?.map((tc, index) => ({
      id: tc.id ?? `call_${Date.now()}_${index}`,
      type: "function",
      function: {
        name: tc.name,
        arguments: JSON.stringify(tc.arguments),
      },
    }))

    const response: Record<string, unknown> = {
      id: `chatcmpl-${Date.now()}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: request.model ?? "test-model",
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: mockResponse.content ?? null,
            tool_calls: toolCalls,
          },
          finish_reason: toolCalls ? "tool_calls" : "stop",
        },
      ],
      usage: {
        prompt_tokens: 100,
        completion_tokens: 50,
        total_tokens: 150,
      },
    }

    return response
  }

  private async handleStreamingResponse(c: any, response: Record<string, unknown>): Promise<Response> {
    const { readable, writable } = new TransformStream()
    const writer = writable.getWriter()

    ;(async () => {
      const choice = response.choices[0] as Record<string, unknown>
      const message = choice.message as Record<string, unknown>

      const chunk1 = {
        id: response.id,
        object: "chat.completion.chunk",
        created: response.created,
        model: response.model,
        choices: [
          {
            index: 0,
            delta: { role: "assistant", content: message.content ?? "" },
            finish_reason: null,
          },
        ],
      }

      await writer.write(new TextEncoder().encode(`data: ${JSON.stringify(chunk1)}\n\n`))

      if (message.tool_calls) {
        const toolCalls = message.tool_calls as Array<Record<string, unknown>>
        for (const tc of toolCalls) {
          const chunk = {
            id: response.id,
            object: "chat.completion.chunk",
            created: response.created,
            model: response.model,
            choices: [
              {
                index: 0,
                delta: { tool_calls: [tc] },
                finish_reason: null,
              },
            ],
          }
          await writer.write(new TextEncoder().encode(`data: ${JSON.stringify(chunk)}\n\n`))
        }
      }

      const finalChunk = {
        id: response.id,
        object: "chat.completion.chunk",
        created: response.created,
        model: response.model,
        choices: [
          {
            index: 0,
            delta: {},
            finish_reason: choice.finish_reason,
          },
        ],
      }

      await writer.write(new TextEncoder().encode(`data: ${JSON.stringify(finalChunk)}\n\n`))
      await writer.write(new TextEncoder().encode("data: [DONE]\n\n"))
      await writer.close()
    })()

    return new Response(readable, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      },
    })
  }

  setResponses(responses: MockLLMResponse[]): void {
    this.responses = responses
    this.responseIndex = 0
  }

  getCallLog(): MockLLMCallLog[] {
    return [...this.callLog]
  }

  clearCallLog(): void {
    this.callLog = []
  }

  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = Bun.serve({
        port: this.port,
        hostname: "localhost",
        fetch: this.app.fetch,
      })
      resolve()
    })
  }

  async stop(): Promise<void> {
    if (this.server) {
      this.server.stop()
      this.server = null
    }
  }

  getPort(): number {
    return this.port
  }

  getUrl(): string {
    return `http://localhost:${this.port}`
  }
}
