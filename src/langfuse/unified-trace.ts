import { LangfuseClient } from "./client.ts"
import { SecurityTraceEmitter } from "./security-trace.ts"
import { OptimizationTraceEmitter } from "./optimization-trace.ts"
import { OTLPExporter, type OTLPConfig } from "./otel-exporter.ts"

interface TraceSession {
  traceId: string
  security: SecurityTraceEmitter
  optimization: OptimizationTraceEmitter
  metadata?: Record<string, unknown>
  createdAt: number
}

export class UnifiedTraceManager {
  private client: LangfuseClient
  private traces: Map<string, TraceSession> = new Map()
  private otelExporter: OTLPExporter | null = null

  constructor(client: LangfuseClient, otelConfig?: OTLPConfig & { enabled?: boolean }) {
    this.client = client
    if (otelConfig?.enabled && otelConfig.endpoint) {
      this.otelExporter = new OTLPExporter({
        endpoint: otelConfig.endpoint,
        headers: otelConfig.headers,
        serviceName: otelConfig.serviceName,
      })
    }
  }

  async createSession(
    sessionId: string,
    metadata?: Record<string, unknown>
  ): Promise<{
    traceId: string
    security: SecurityTraceEmitter
    optimization: OptimizationTraceEmitter
  }> {
    const traceId = sessionId
    const startTime = new Date()

    const security = new SecurityTraceEmitter(this.client, traceId)
    const optimization = new OptimizationTraceEmitter(this.client, traceId)

    const session: TraceSession = {
      traceId,
      security,
      optimization,
      metadata,
      createdAt: Date.now(),
    }

    this.traces.set(sessionId, session)

    await this.client.createTrace({
      id: traceId,
      name: `si-agents-session-${sessionId}`,
      metadata: {
        ...metadata,
        sessionType: "si-agents",
        createdAt: new Date().toISOString(),
      },
    })

    if (this.otelExporter) {
      const span = this.otelExporter.createSpan({
        traceId,
        name: "session-start",
        startTime,
        attributes: {
          "session.id": sessionId,
          "session.type": "si-agents",
          ...Object.fromEntries(
            Object.entries(metadata ?? {}).map(([k, v]) => [k, String(v)])
          ),
        },
      })
      await this.otelExporter.exportSpan(span)
    }

    return {
      traceId,
      security,
      optimization,
    }
  }

  getTrace(sessionId: string): {
    traceId: string
    security: SecurityTraceEmitter
    optimization: OptimizationTraceEmitter
  } | null {
    const session = this.traces.get(sessionId)
    if (!session) {
      return null
    }

    return {
      traceId: session.traceId,
      security: session.security,
      optimization: session.optimization,
    }
  }

  async endSession(sessionId: string): Promise<void> {
    const session = this.traces.get(sessionId)
    if (!session) {
      return
    }

    await this.client.createEvent({
      traceId: session.traceId,
      name: "session-end",
      metadata: {
        eventType: "session_end",
        sessionId,
        duration: Date.now() - session.createdAt,
        endedAt: new Date().toISOString(),
      },
    })

    if (this.otelExporter) {
      const span = this.otelExporter.createSpan({
        traceId: session.traceId,
        name: "session-end",
        startTime: new Date(session.createdAt),
        endTime: new Date(),
        attributes: {
          "session.id": sessionId,
          "session.duration_ms": String(Date.now() - session.createdAt),
        },
      })
      await this.otelExporter.exportSpan(span)
    }

    this.traces.delete(sessionId)
  }

  async startSpan(
    traceId: string,
    name: string,
    attributes?: Record<string, string>
  ): Promise<void> {
    if (this.otelExporter) {
      const span = this.otelExporter.createSpan({
        traceId,
        name,
        startTime: new Date(),
        attributes,
      })
      await this.otelExporter.exportSpan(span)
    }
  }

  async endSpan(
    traceId: string,
    name: string,
    startTime: Date,
    attributes?: Record<string, string>
  ): Promise<void> {
    if (this.otelExporter) {
      const span = this.otelExporter.createSpan({
        traceId,
        name,
        startTime,
        endTime: new Date(),
        attributes,
      })
      await this.otelExporter.exportSpan(span)
    }
  }

  async addEvent(
    traceId: string,
    name: string,
    attributes?: Record<string, string>
  ): Promise<void> {
    if (this.otelExporter) {
      const span = this.otelExporter.createSpan({
        traceId,
        name,
        startTime: new Date(),
        attributes: {
          "event.type": name,
          ...attributes,
        },
      })
      await this.otelExporter.exportSpan(span)
    }
  }

  async flushAll(): Promise<void> {
    await this.client.flush()
  }

  async shutdown(): Promise<void> {
    for (const sessionId of this.traces.keys()) {
      await this.endSession(sessionId)
    }
    await this.client.shutdown()
  }

  hasSession(sessionId: string): boolean {
    return this.traces.has(sessionId)
  }

  getSessionIds(): string[] {
    return Array.from(this.traces.keys())
  }

  getSessionCount(): number {
    return this.traces.size
  }

  isClientEnabled(): boolean {
    return this.client.isEnabled()
  }
}

export function createUnifiedTraceManager(config: {
  publicKey?: string
  secretKey?: string
  baseUrl?: string
  opentelemetry?: {
    enabled?: boolean
    endpoint?: string
    headers?: Record<string, string>
    serviceName?: string
  }
}): UnifiedTraceManager {
  const client = new LangfuseClient({
    publicKey: config.publicKey,
    secretKey: config.secretKey,
    baseUrl: config.baseUrl,
  })

  return new UnifiedTraceManager(client, config.opentelemetry as OTLPConfig & { enabled?: boolean })
}
