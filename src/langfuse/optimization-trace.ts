import type { LangfuseClient } from "./client.ts"

export interface OptimizationEvent {
  type: "jit-boost" | "jit-optimize"
  skillId?: string
  modelName?: string
  performanceGain?: number
  securityAuditResult: "passed" | "blocked" | "warning"
}

export interface BoostPromotionEvent {
  candidateId: string
  skillId: string
  matchCount: number
  securityAuditPassed: boolean
}

export interface OptimizeCompleteEvent {
  skillId: string
  roundCount: number
  bestRound: number
  scoreImprovement: number
  securityRisks: string[]
}

export interface OptimizeRoundEvent {
  round: number
  score: number
  changes: string[]
  securityAuditResult: "passed" | "blocked" | "warning"
}

export class OptimizationTraceEmitter {
  private client: LangfuseClient
  private traceId: string
  private activeSpans: Map<string, string> = new Map()

  constructor(client: LangfuseClient, traceId: string) {
    this.client = client
    this.traceId = traceId
  }

  async emitBoostPromotion(event: BoostPromotionEvent): Promise<void> {
    const spanId = await this.client.createSpan({
      traceId: this.traceId,
      name: `jit-boost-promotion-${event.skillId}`,
      type: "optimization",
      metadata: {
        eventType: "jit_boost_promotion",
        candidateId: event.candidateId,
        skillId: event.skillId,
        matchCount: event.matchCount,
        securityAuditPassed: event.securityAuditPassed,
        timestamp: new Date().toISOString(),
      },
    })

    this.activeSpans.set(`boost-${event.skillId}`, spanId)
    await this.client.endSpan(spanId, {
      status: event.securityAuditPassed ? "promoted" : "blocked",
      promotionComplete: true,
    })
  }

  async emitOptimizeComplete(event: OptimizeCompleteEvent): Promise<void> {
    const spanId = await this.client.createSpan({
      traceId: this.traceId,
      name: `jit-optimize-complete-${event.skillId}`,
      type: "optimization",
      metadata: {
        eventType: "jit_optimize_complete",
        skillId: event.skillId,
        roundCount: event.roundCount,
        bestRound: event.bestRound,
        scoreImprovement: event.scoreImprovement,
        securityRisks: event.securityRisks,
        timestamp: new Date().toISOString(),
      },
    })

    this.activeSpans.set(`optimize-${event.skillId}`, spanId)
    await this.client.endSpan(spanId, {
      status: event.securityRisks.length > 0 ? "warning" : "completed",
      optimizationComplete: true,
    })
  }

  async emitOptimizeRound(event: OptimizeRoundEvent): Promise<void> {
    await this.client.createEvent({
      traceId: this.traceId,
      name: `optimize-round-${event.round}`,
      metadata: {
        eventType: "optimize_round",
        round: event.round,
        score: event.score,
        changes: event.changes,
        securityAuditResult: event.securityAuditResult,
        timestamp: new Date().toISOString(),
      },
    })
  }

  async emitOptimizationStart(params: {
    type: "jit-boost" | "jit-optimize"
    skillId: string
    modelName?: string
  }): Promise<string> {
    const spanId = await this.client.createSpan({
      traceId: this.traceId,
      name: `optimization-start-${params.type}`,
      type: "optimization",
      metadata: {
        eventType: "optimization_start",
        optimizationType: params.type,
        skillId: params.skillId,
        modelName: params.modelName,
        startTime: new Date().toISOString(),
      },
    })

    const key = `opt-${params.type}-${params.skillId}`
    this.activeSpans.set(key, spanId)
    return spanId
  }

  async emitOptimizationEnd(params: {
    type: "jit-boost" | "jit-optimize"
    skillId: string
    result: "success" | "failed" | "partial"
    metrics?: Record<string, number>
  }): Promise<void> {
    const key = `opt-${params.type}-${params.skillId}`
    const spanId = this.activeSpans.get(key)

    if (spanId) {
      await this.client.endSpan(spanId, {
        status: params.result,
        metrics: params.metrics,
        endTime: new Date().toISOString(),
      })
      this.activeSpans.delete(key)
    }
  }

  async emitPerformanceMetric(params: {
    metricName: string
    value: number
    unit: string
    tags?: Record<string, string>
  }): Promise<void> {
    await this.client.createEvent({
      traceId: this.traceId,
      name: `metric-${params.metricName}`,
      metadata: {
        eventType: "performance_metric",
        metricName: params.metricName,
        value: params.value,
        unit: params.unit,
        tags: params.tags,
        timestamp: new Date().toISOString(),
      },
    })
  }

  getTraceId(): string {
    return this.traceId
  }
}
