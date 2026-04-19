import { LangfuseClient } from "./client.ts"
import { SecurityTraceEmitter } from "./security-trace.ts"
import { OptimizationTraceEmitter } from "./optimization-trace.ts"

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

  constructor(client: LangfuseClient) {
    this.client = client
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

    this.traces.delete(sessionId)
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
}): UnifiedTraceManager {
  const client = new LangfuseClient({
    publicKey: config.publicKey,
    secretKey: config.secretKey,
    baseUrl: config.baseUrl,
  })

  return new UnifiedTraceManager(client)
}
