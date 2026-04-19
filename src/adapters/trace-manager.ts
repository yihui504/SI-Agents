import type { Instruction } from "../types/instruction.ts"

export interface TraceState {
  id: string
  instructions: Instruction[]
  currentStep: number
  startTime: number
  endTime?: number
  status: "running" | "completed" | "failed" | "blocked"
  error?: string
}

export class TraceManager {
  private traces: Map<string, TraceState> = new Map()

  createTrace(): string {
    const traceId = crypto.randomUUID()
    const trace: TraceState = {
      id: traceId,
      instructions: [],
      currentStep: 0,
      startTime: Date.now(),
      status: "running",
    }
    this.traces.set(traceId, trace)
    return traceId
  }

  getTrace(traceId: string): TraceState | null {
    return this.traces.get(traceId) ?? null
  }

  updateTrace(traceId: string, update: Partial<TraceState>): void {
    const trace = this.traces.get(traceId)
    if (trace) {
      Object.assign(trace, update)
    }
  }

  addInstruction(traceId: string, instruction: Instruction): void {
    const trace = this.traces.get(traceId)
    if (trace) {
      trace.instructions.push(instruction)
      trace.currentStep++
    }
  }

  endTrace(traceId: string, status: "completed" | "failed" | "blocked" = "completed", error?: string): void {
    const trace = this.traces.get(traceId)
    if (trace) {
      trace.endTime = Date.now()
      trace.status = status
      if (error) trace.error = error
    }
  }

  deleteTrace(traceId: string): void {
    this.traces.delete(traceId)
  }

  getActiveTraces(): TraceState[] {
    return Array.from(this.traces.values()).filter((t) => t.status === "running")
  }

  getTraceDuration(traceId: string): number {
    const trace = this.traces.get(traceId)
    if (!trace) return 0
    const endTime = trace.endTime ?? Date.now()
    return endTime - trace.startTime
  }

  clear(): void {
    this.traces.clear()
  }
}

export const traceManager = new TraceManager()
