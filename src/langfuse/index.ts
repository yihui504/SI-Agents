export { LangfuseClient } from "./client.ts"
export type { LangfuseConfig, TraceParams, SpanParams, EventParams } from "./client.ts"

export { SecurityTraceEmitter } from "./security-trace.ts"
export type { SecurityEvent, TaintPropagationEvent } from "./security-trace.ts"

export { OptimizationTraceEmitter } from "./optimization-trace.ts"
export type {
  OptimizationEvent,
  BoostPromotionEvent,
  OptimizeCompleteEvent,
  OptimizeRoundEvent,
} from "./optimization-trace.ts"

export { UnifiedTraceManager, createUnifiedTraceManager } from "./unified-trace.ts"
