import { Hono } from "hono"
import { cors } from "hono/cors"
import { streamSSE } from "hono/streaming"
import type { Context } from "hono"
import type { SIAgentsConfig, ModelRoute } from "../types/config.ts"
import type { ChatCompletionRequest, ChatCompletionResponse, OpenAIError, TraceContext } from "./types.ts"
import type { Instruction } from "../types/instruction.ts"
import { ModelRouter } from "./model-router.ts"
import { executePreCall } from "./pre-call.ts"
import { executePostCall } from "./post-call.ts"
import { processStreamingResponse } from "./streaming.ts"
import { PolicyRegistry } from "../policy/registry.ts"
import { TaintTracker } from "../taint/tracker.ts"

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

export class ProxyServer {
  private app: Hono
  private config: ProxyServerConfig
  private modelRouter: ModelRouter
  private traceContexts: Map<string, TraceContext> = new Map()
  private pendingConfirmations: Map<string, string> = new Map()
  private server: ReturnType<typeof Bun.serve> | null = null

  constructor(config: ProxyServerConfig) {
    this.config = config
    this.app = new Hono()
    this.modelRouter = new ModelRouter(config.modelRoutes, config.defaultModel)
    this.setupRoutes()
  }

  private setupRoutes(): void {
    this.app.use("*", cors())

    this.app.get("/v1/models", (c) => this.handleModels(c))
    this.app.post("/v1/chat/completions", (c) => this.handleChatCompletions(c))

    this.app.get("/health", (c) => c.json({ status: "ok", timestamp: new Date().toISOString() }))
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

  private async handleChatCompletions(c: Context): Promise<Response> {
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

    const proxyConfig = {
      policyRegistry: this.config.policyRegistry,
      taintTracker: this.config.taintTracker,
      modelRoutes: new Map(this.config.modelRoutes.map((r) => [r.name, r])),
      defaultModel: this.config.defaultModel,
      observeOnly: this.config.observeOnly,
      securityDir: this.config.securityDir,
    }

    const preCallResult = await executePreCall(request, proxyConfig, this.pendingConfirmations)

    if (preCallResult.shouldBypass && preCallResult.bypassResponse) {
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

    this.traceContexts.set(traceId, {
      traceId,
      request: modifiedRequest,
      instructions: [],
      startTime: Date.now(),
    })

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
        return this.handleStreamingResponse(upstreamResponse, traceId, proxyConfig)
      }

      const responseData = (await upstreamResponse.json()) as ChatCompletionResponse

      const traceContext = this.traceContexts.get(traceId)
      const previousInstructions = traceContext?.instructions ?? []

      const postCallResult = await executePostCall(
        responseData,
        traceId,
        proxyConfig,
        previousInstructions,
        this.pendingConfirmations
      )

      if (traceContext && postCallResult.policyBlocked) {
        const newInstructions = this.parseInstructionsFromResponse(postCallResult.response)
        traceContext.instructions = [...previousInstructions, ...newInstructions]
      }

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
    const traceContext = this.traceContexts.get(traceId)
    const previousInstructions = traceContext?.instructions ?? []

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
    this.traceContexts.clear()
    this.pendingConfirmations.clear()
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
