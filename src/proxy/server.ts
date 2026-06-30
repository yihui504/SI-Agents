import { Hono } from "hono"
import { cors } from "hono/cors"
import { streamSSE } from "hono/streaming"
import type { Context } from "hono"
import { join } from "node:path"
import type { SIAgentsConfig, ModelRoute } from "../types/config.ts"
import type { ChatCompletionRequest, ChatCompletionResponse, OpenAIError, TraceContext, ConfirmationEntry } from "./types.ts"
import type { Instruction } from "../types/instruction.ts"
import { ModelRouter } from "./model-router.ts"
import { executePreCall } from "./pre-call.ts"
import { executePostCall } from "./post-call.ts"
import { processStreamingResponse } from "./streaming.ts"
import { PolicyRegistry } from "../policy/registry.ts"
import { TaintTracker } from "../taint/tracker.ts"
import { FileStore } from "../persistence/file-store.ts"
import { Mutex } from "../utils/mutex.ts"

export interface ProxyServerConfig {
  port: number
  host: string
  modelRoutes: ModelRoute[]
  defaultModel?: string
  policyRegistry: PolicyRegistry
  taintTracker: TaintTracker
  observeOnly: boolean
  securityDir: string
}

const CONFIRMATION_TTL_MS = 5 * 60 * 1000

export class ProxyServer {
  private app: Hono
  private config: ProxyServerConfig
  private modelRouter: ModelRouter
  private traceContexts: Map<string, TraceContext> = new Map()
  private pendingConfirmations: Map<string, ConfirmationEntry> = new Map()
  private fileStore: FileStore | null = null
  private server: ReturnType<typeof Bun.serve> | null = null
  private startTime: number = Date.now()
  private requestCount: number = 0
  private blockedCount: number = 0
  private streamingCount: number = 0
  private totalLatencyMs: number = 0
  private confirmationCleanupTimer: ReturnType<typeof setInterval> | null = null
  private stateMutex: Mutex = new Mutex()

  constructor(config: ProxyServerConfig) {
    this.config = config
    this.app = new Hono()
    this.modelRouter = new ModelRouter(config.modelRoutes, config.defaultModel)
    if (this.config.securityDir) {
      this.fileStore = new FileStore({
        dir: join(this.config.securityDir, "traces"),
        enabled: true,
      })
    }
    this.confirmationCleanupTimer = setInterval(() => {
      this.stateMutex.withLock(async () => {
        const now = Date.now()
        for (const [traceId, entry] of this.pendingConfirmations) {
          if (now - entry.createdAt > CONFIRMATION_TTL_MS) {
            this.pendingConfirmations.delete(traceId)
          }
        }
      })
    }, 60000)
    this.setupRoutes()
  }

  private setupRoutes(): void {
    this.app.use("*", cors())

    this.app.get("/v1/models", (c) => this.handleModels(c))
    this.app.post("/v1/chat/completions", (c) => this.handleChatCompletions(c))

    this.app.get("/health", (c) => this.handleHealth(c))
    this.app.get("/metrics", (c) => this.handleMetrics(c))
  }

  private async handleModels(c: Context): Promise<Response> {
    const models = this.modelRouter.listModels()
    return c.json({
      object: "list",
      data: models.map((m) => ({
        id: m.id,
        object: "model",
        created: Math.floor(Date.now() / 1000),
        owned_by: "si-agents",
      })),
    })
  }

  private handleHealth(c: Context): Response {
    const models = this.modelRouter.listModels()
    return c.json({
      status: "ok",
      timestamp: new Date().toISOString(),
      uptime: Math.floor((Date.now() - this.startTime) / 1000),
      activeTraces: this.traceContexts.size,
      pendingConfirmations: this.pendingConfirmations.size,
      policyEnabled: !this.config.observeOnly,
      taintEnabled: this.config.taintTracker !== undefined,
      models: models.map((m) => m.id),
    })
  }

  private handleMetrics(c: Context): Response {
    const uptimeSeconds = Math.floor((Date.now() - this.startTime) / 1000)
    return c.json({
      requests_total: this.requestCount,
      requests_blocked: this.blockedCount,
      requests_streaming: this.streamingCount,
      avg_latency_ms: this.requestCount > 0 ? Math.round(this.totalLatencyMs / this.requestCount) : 0,
      active_traces: this.traceContexts.size,
      pending_confirmations: this.pendingConfirmations.size,
      uptime_seconds: uptimeSeconds,
    })
  }

  private async handleChatCompletions(c: Context): Promise<Response> {
    const requestStart = Date.now()
    this.requestCount++

    let request: ChatCompletionRequest
    try {
      request = await c.req.json<ChatCompletionRequest>()
    } catch (e) {
      return c.json(
        {
          error: {
            message: "Invalid JSON in request body",
            type: "invalid_request_error",
            param: null,
            code: "invalid_json",
          },
        },
        400
      )
    }

    if (typeof request.model !== "string" || request.model.trim() === "") {
      return c.json(
        {
          error: {
            message: "'model' must be a non-empty string",
            type: "invalid_request_error",
            param: "model",
            code: "invalid_model",
          },
        },
        400
      )
    }

    if (!Array.isArray(request.messages) || request.messages.length === 0) {
      return c.json(
        {
          error: {
            message: "'messages' must be a non-empty array",
            type: "invalid_request_error",
            param: "messages",
            code: "invalid_messages",
          },
        },
        400
      )
    }

    const proxyConfig = {
      policyRegistry: this.config.policyRegistry,
      taintTracker: this.config.taintTracker,
      modelRoutes: new Map(this.config.modelRoutes.map((r) => [r.name, r])),
      defaultModel: this.config.defaultModel,
      observeOnly: this.config.observeOnly,
      securityDir: this.config.securityDir,
    }

    const preCallResult = await this.stateMutex.withLock(async () => {
      return executePreCall(request, proxyConfig, this.pendingConfirmations)
    })

    if (preCallResult.shouldBypass && preCallResult.bypassResponse) {
      this.blockedCount++
      this.totalLatencyMs += Date.now() - requestStart
      return c.json(preCallResult.bypassResponse)
    }

    const traceId = preCallResult.traceId
    const modifiedRequest = preCallResult.modifiedRequest ?? request

    const route = this.modelRouter.resolve(modifiedRequest.model)
    if (!route) {
      return c.json(
        {
          error: {
            message: `Model '${modifiedRequest.model}' not found`,
            type: "invalid_request_error",
            param: "model",
            code: "model_not_found",
          },
        },
        404
      )
    }

    await this.stateMutex.withLock(async () => {
      this.traceContexts.set(traceId, {
        traceId,
        request: modifiedRequest,
        instructions: [],
        startTime: Date.now(),
      })
    })

    if (this.fileStore) {
      this.fileStore.save(traceId, {
        traceId,
        request: modifiedRequest,
        instructions: [],
        startTime: Date.now(),
      })
    }

    try {
      const upstreamResponse = await this.modelRouter.forward(modifiedRequest, route)

      if (!upstreamResponse.ok) {
        const errorBody = await upstreamResponse.text()
        return c.json(
          {
            error: {
              message: errorBody || "Upstream request failed",
              type: "upstream_error",
              param: null,
              code: String(upstreamResponse.status),
            },
          },
          upstreamResponse.status as 400 | 401 | 403 | 404 | 429 | 500 | 502 | 503
        )
      }

      if (modifiedRequest.stream) {
        this.streamingCount++
        this.totalLatencyMs += Date.now() - requestStart
        return this.handleStreamingResponse(upstreamResponse, traceId, proxyConfig)
      }

      const responseData = (await upstreamResponse.json()) as ChatCompletionResponse

      const postCallResult = await this.stateMutex.withLock(async () => {
        const traceContext = this.traceContexts.get(traceId)
        const previousInstructions = traceContext?.instructions ?? []

        const result = await executePostCall(
          responseData,
          traceId,
          proxyConfig,
          previousInstructions,
          this.pendingConfirmations
        )

        if (traceContext && result.policyBlocked) {
          const newInstructions = this.parseInstructionsFromResponse(result.response)
          traceContext.instructions = [...previousInstructions, ...newInstructions]
        }

        return result
      })

      this.totalLatencyMs += Date.now() - requestStart
      return c.json(postCallResult.response)
    } catch (e) {
      const message = e instanceof Error ? e.message : "Unknown error"
      return c.json(
        {
          error: {
            message,
            type: "internal_error",
            param: null,
            code: "internal_error",
          },
        },
        500
      )
    }
  }

  private async handleStreamingResponse(
    upstreamResponse: Response,
    traceId: string,
    proxyConfig: {
      policyRegistry: PolicyRegistry
      taintTracker: TaintTracker
      modelRoutes: Map<string, ModelRoute>
      defaultModel?: string
      observeOnly: boolean
      securityDir: string
    }
  ): Promise<Response> {
    const { previousInstructions } = await this.stateMutex.withLock(async () => {
      const traceContext = this.traceContexts.get(traceId)
      const previousInstructions = traceContext?.instructions ?? []
      return { previousInstructions }
    })

    return processStreamingResponse(
      upstreamResponse,
      traceId,
      proxyConfig,
      previousInstructions,
      this.pendingConfirmations
    )
  }

  private parseInstructionsFromResponse(response: ChatCompletionResponse): Instruction[] {
    const instructions: Instruction[] = []
    const choice = response.choices[0]
    if (!choice) return instructions

    const message = choice.message

    if (message.content && typeof message.content === "string") {
      instructions.push({
        id: crypto.randomUUID(),
        content: { text: message.content },
        runtime_step: 0,
        parent_id: null,
        source_message_id: null,
        security_type: {
          confidentiality: "LOW",
          trustworthiness: "HIGH",
          prop_confidentiality: "UNKNOWN",
          prop_trustworthiness: "UNKNOWN",
          confidence: "UNKNOWN",
          reversible: true,
          authority: "UNKNOWN",
          risk: "UNKNOWN",
          custom: {},
        },
        rule_types: [],
        instruction_category: "EXECUTION.Human",
        instruction_type: "RESPOND",
      })
    }

    if (message.tool_calls) {
      for (const tc of message.tool_calls) {
        let args: Record<string, unknown> = {}
        try {
          args = JSON.parse(tc.function.arguments)
        } catch {
          // ignore
        }
        instructions.push({
          id: crypto.randomUUID(),
          content: {
            tool_name: tc.function.name,
            tool_call_id: tc.id,
            arguments: args,
          },
          runtime_step: instructions.length,
          parent_id: null,
          source_message_id: null,
          security_type: {
            confidentiality: "UNKNOWN",
            trustworthiness: "UNKNOWN",
            prop_confidentiality: "UNKNOWN",
            prop_trustworthiness: "UNKNOWN",
            confidence: "UNKNOWN",
            reversible: false,
            authority: "UNKNOWN",
            risk: "UNKNOWN",
            custom: {},
          },
          rule_types: [],
          instruction_category: "EXECUTION.Env",
          instruction_type: "EXEC",
        })
      }
    }

    return instructions
  }

  start(): void {
    console.log(`SI-Agents Proxy Server starting on ${this.config.host}:${this.config.port}`)
    this.server = Bun.serve({
      port: this.config.port,
      hostname: this.config.host,
      fetch: this.app.fetch,
    })
  }

  stop(): void {
    this.server?.stop()
    this.server = null
    if (this.confirmationCleanupTimer) {
      clearInterval(this.confirmationCleanupTimer)
      this.confirmationCleanupTimer = null
    }
    if (!this.fileStore?.isEnabled()) {
      this.traceContexts.clear()
    }
    this.pendingConfirmations.clear()
    this.requestCount = 0
    this.blockedCount = 0
    this.streamingCount = 0
    this.totalLatencyMs = 0
    this.startTime = Date.now()
    console.log("SI-Agents Proxy Server stopped")
  }
}

export function createProxyServer(config: SIAgentsConfig, policyRegistry: PolicyRegistry, taintTracker: TaintTracker): ProxyServer {
  return new ProxyServer({
    port: config.server.port,
    host: config.server.host,
    modelRoutes: config.models.routes,
    defaultModel: config.models.default,
    policyRegistry,
    taintTracker,
    observeOnly: config.policy.observe_only,
    securityDir: config.security.security_dir,
  })
}
