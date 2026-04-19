export interface LangfuseConfig {
  publicKey?: string
  secretKey?: string
  baseUrl?: string
}

export interface TraceParams {
  id: string
  name?: string
  metadata?: Record<string, unknown>
}

export interface SpanParams {
  traceId: string
  name: string
  type: "security" | "optimization" | "llm" | "tool"
  metadata?: Record<string, unknown>
}

export interface EventParams {
  traceId: string
  name: string
  metadata?: Record<string, unknown>
}

interface LangfuseTrace {
  id: string
  name?: string
  metadata?: Record<string, unknown>
}

interface LangfuseSpan {
  id: string
  traceId: string
  name: string
  type: string
  metadata?: Record<string, unknown>
  endTime?: string
}

export class LangfuseClient {
  private config: LangfuseConfig
  private enabled: boolean
  private traces: Map<string, LangfuseTrace> = new Map()
  private spans: Map<string, LangfuseSpan> = new Map()
  private eventQueue: Array<() => Promise<void>> = []
  private isFlushing: boolean = false

  constructor(config: LangfuseConfig) {
    this.config = {
      baseUrl: config.baseUrl || "https://cloud.langfuse.com",
      publicKey: config.publicKey,
      secretKey: config.secretKey,
    }
    this.enabled = !!(config.publicKey && config.secretKey)
    
    if (!this.enabled) {
      console.log("[Langfuse] Client disabled - missing public_key or secret_key")
    }
  }

  private getAuthHeader(): string {
    const credentials = `${this.config.publicKey}:${this.config.secretKey}`
    return `Basic ${btoa(credentials)}`
  }

  private async sendRequest(endpoint: string, body: Record<string, unknown>): Promise<boolean> {
    if (!this.enabled) {
      return false
    }

    try {
      const url = `${this.config.baseUrl}/api/public${endpoint}`
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": this.getAuthHeader(),
        },
        body: JSON.stringify(body),
      })

      if (!response.ok) {
        console.error(`[Langfuse] Request failed: ${response.status} ${response.statusText}`)
        return false
      }

      return true
    } catch (error) {
      console.error(`[Langfuse] Request error: ${error}`)
      return false
    }
  }

  async createTrace(params: TraceParams): Promise<string> {
    const traceId = params.id

    this.traces.set(traceId, {
      id: traceId,
      name: params.name,
      metadata: params.metadata,
    })

    this.eventQueue.push(async () => {
      await this.sendRequest("/traces", {
        id: traceId,
        name: params.name,
        metadata: params.metadata,
        timestamp: new Date().toISOString(),
      })
    })

    return traceId
  }

  async createSpan(params: SpanParams): Promise<string> {
    const spanId = `${params.traceId}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`

    this.spans.set(spanId, {
      id: spanId,
      traceId: params.traceId,
      name: params.name,
      type: params.type,
      metadata: params.metadata,
    })

    this.eventQueue.push(async () => {
      await this.sendRequest("/spans", {
        id: spanId,
        traceId: params.traceId,
        name: params.name,
        type: params.type,
        metadata: params.metadata,
        startTime: new Date().toISOString(),
      })
    })

    return spanId
  }

  async createEvent(params: EventParams): Promise<void> {
    const eventId = `${params.traceId}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`

    this.eventQueue.push(async () => {
      await this.sendRequest("/events", {
        id: eventId,
        traceId: params.traceId,
        name: params.name,
        metadata: params.metadata,
        timestamp: new Date().toISOString(),
      })
    })
  }

  async endSpan(spanId: string, metadata?: Record<string, unknown>): Promise<void> {
    const span = this.spans.get(spanId)
    if (!span) {
      console.warn(`[Langfuse] Span not found: ${spanId}`)
      return
    }

    span.endTime = new Date().toISOString()
    if (metadata) {
      span.metadata = { ...span.metadata, ...metadata }
    }

    this.eventQueue.push(async () => {
      await this.sendRequest("/spans", {
        id: spanId,
        traceId: span.traceId,
        name: span.name,
        type: span.type,
        metadata: span.metadata,
        startTime: span.endTime,
        endTime: span.endTime,
        level: "DEFAULT",
        statusMessage: "completed",
      })
    })
  }

  async flush(): Promise<void> {
    if (this.isFlushing || !this.enabled) {
      return
    }

    this.isFlushing = true

    const events = [...this.eventQueue]
    this.eventQueue = []

    try {
      await Promise.all(events.map(event => event()))
    } catch (error) {
      console.error(`[Langfuse] Flush error: ${error}`)
    } finally {
      this.isFlushing = false
    }
  }

  async shutdown(): Promise<void> {
    await this.flush()
    this.traces.clear()
    this.spans.clear()
  }

  isEnabled(): boolean {
    return this.enabled
  }
}
