export interface LangfuseConfig {
  publicKey?: string
  secretKey?: string
  baseUrl?: string
  batchSize?: number
  flushIntervalMs?: number
  maxEntries?: number
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
  private batchBuffer: Array<() => Promise<void>> = []
  private batchSize: number
  private flushIntervalMs: number
  private flushTimer: ReturnType<typeof setInterval> | null = null
  private cleanupTimer: ReturnType<typeof setInterval> | null = null
  private flushPromise: Promise<void> = Promise.resolve()
  private maxEntries: number

  constructor(config: LangfuseConfig) {
    this.config = {
      baseUrl: config.baseUrl || "https://cloud.langfuse.com",
      publicKey: config.publicKey,
      secretKey: config.secretKey,
    }
    this.batchSize = config.batchSize ?? 10
    this.flushIntervalMs = config.flushIntervalMs ?? 5000
    this.maxEntries = config.maxEntries ?? 1000
    this.enabled = !!(config.publicKey && config.secretKey)

    if (!this.enabled) {
      console.log("[Langfuse] Client disabled - missing public_key or secret_key")
    }

    this.flushTimer = setInterval(() => {
      this.flush()
    }, this.flushIntervalMs)

    this.cleanupTimer = setInterval(() => this.cleanup(), 60000)
  }

  private cleanup(): void {
    if (this.traces.size > this.maxEntries) {
      const entries = [...this.traces.entries()]
      const toRemove = entries.slice(0, entries.length - this.maxEntries)
      for (const [key] of toRemove) {
        this.traces.delete(key)
      }
    }
    if (this.spans.size > this.maxEntries) {
      const entries = [...this.spans.entries()]
      const toRemove = entries.slice(0, entries.length - this.maxEntries)
      for (const [key] of toRemove) {
        this.spans.delete(key)
      }
    }
  }

  private getAuthHeader(): string {
    const credentials = `${this.config.publicKey}:${this.config.secretKey}`
    return `Basic ${btoa(credentials)}`
  }

  private async sendWithRetry(endpoint: string, body: Record<string, unknown>, maxRetries: number = 3): Promise<boolean> {
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      const success = await this.sendRequest(endpoint, body)
      if (success) {
        return true
      }
      if (attempt < maxRetries - 1) {
        const delay = 1000 * Math.pow(2, attempt)
        await new Promise(resolve => setTimeout(resolve, delay))
      }
    }
    return false
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

    this.batchBuffer.push(async () => {
      await this.sendWithRetry("/traces", {
        id: traceId,
        name: params.name,
        metadata: params.metadata,
        timestamp: new Date().toISOString(),
      })
    })

    if (this.batchBuffer.length >= this.batchSize) {
      this.flush()
    }

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

    this.batchBuffer.push(async () => {
      await this.sendWithRetry("/spans", {
        id: spanId,
        traceId: params.traceId,
        name: params.name,
        type: params.type,
        metadata: params.metadata,
        startTime: new Date().toISOString(),
      })
    })

    if (this.batchBuffer.length >= this.batchSize) {
      this.flush()
    }

    return spanId
  }

  async createEvent(params: EventParams): Promise<void> {
    const eventId = `${params.traceId}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`

    this.batchBuffer.push(async () => {
      await this.sendWithRetry("/events", {
        id: eventId,
        traceId: params.traceId,
        name: params.name,
        metadata: params.metadata,
        timestamp: new Date().toISOString(),
      })
    })

    if (this.batchBuffer.length >= this.batchSize) {
      this.flush()
    }
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

    this.batchBuffer.push(async () => {
      await this.sendWithRetry("/spans", {
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

    if (this.batchBuffer.length >= this.batchSize) {
      this.flush()
    }
  }

  async flush(): Promise<void> {
    this.flushPromise = this.flushPromise.then(async () => {
      if (!this.enabled) return
      const events = [...this.batchBuffer]
      this.batchBuffer = []
      if (events.length === 0) return
      const concurrencyLimit = 3
      for (let i = 0; i < events.length; i += concurrencyLimit) {
        const batch = events.slice(i, i + concurrencyLimit)
        await Promise.all(batch.map(fn => fn()))
      }
    })
    await this.flushPromise
  }

  async shutdown(): Promise<void> {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer)
      this.cleanupTimer = null
    }
    if (this.flushTimer) {
      clearInterval(this.flushTimer)
      this.flushTimer = null
    }
    await this.flush()
    this.traces.clear()
    this.spans.clear()
  }

  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer)
      this.cleanupTimer = null
    }
    if (this.flushTimer) {
      clearInterval(this.flushTimer)
      this.flushTimer = null
    }
  }

  isEnabled(): boolean {
    return this.enabled
  }
}
