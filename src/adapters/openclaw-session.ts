import type { Instruction } from "../types/instruction.ts"
import { InstructionBuilder } from "../instruction/builder.ts"
import {
  parseOpenClawToolCall,
  type OpenClawToolCall,
  type ParsedToolCall,
} from "./openclaw-tools.ts"

export interface OpenClawSession {
  id: string
  traceId: string
  skillDir: string
  workDir: string
  taskPrompt: string
  startTime: number
  status: "running" | "completed" | "failed"
  instructions: Instruction[]
  toolCalls: ParsedToolCall[]
}

export interface CreateSessionParams {
  skillDir: string
  taskPrompt: string
  workDir: string
  traceId?: string
}

export interface SessionOptimizeResult {
  sessionId: string
  traceId: string
  optimized: boolean
  message?: string
}

export class OpenClawSessionManager {
  private sessions: Map<string, OpenClawSession> = new Map()
  private traceToSession: Map<string, string> = new Map()
  private optimizeEnabled: boolean = false
  private optimizeCallback?: (session: OpenClawSession) => Promise<void>

  constructor(options?: {
    optimizeEnabled?: boolean
    optimizeCallback?: (session: OpenClawSession) => Promise<void>
  }) {
    this.optimizeEnabled = options?.optimizeEnabled ?? false
    this.optimizeCallback = options?.optimizeCallback
  }

  async createSession(params: CreateSessionParams): Promise<string> {
    const sessionId = this.generateSessionId()
    const traceId = params.traceId ?? this.generateTraceId()

    const session: OpenClawSession = {
      id: sessionId,
      traceId,
      skillDir: params.skillDir,
      workDir: params.workDir,
      taskPrompt: params.taskPrompt,
      startTime: Date.now(),
      status: "running",
      instructions: [],
      toolCalls: [],
    }

    this.sessions.set(sessionId, session)
    this.traceToSession.set(traceId, sessionId)

    return sessionId
  }

  getSession(sessionId: string): OpenClawSession | null {
    return this.sessions.get(sessionId) ?? null
  }

  getSessionByTraceId(traceId: string): OpenClawSession | null {
    const sessionId = this.traceToSession.get(traceId)
    if (!sessionId) return null
    return this.sessions.get(sessionId) ?? null
  }

  async endSession(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId)
    if (!session) return

    session.status = "completed"
  }

  failSession(sessionId: string, reason?: string): void {
    const session = this.sessions.get(sessionId)
    if (!session) return

    session.status = "failed"
  }

  recordToolCalls(
    sessionId: string,
    toolCalls: OpenClawToolCall[]
  ): ParsedToolCall[] {
    const session = this.sessions.get(sessionId)
    if (!session) return []

    const parsed: ParsedToolCall[] = []
    const builder = new InstructionBuilder(session.traceId, "openclaw")

    for (const tc of toolCalls) {
      const parsedTc = parseOpenClawToolCall(tc)
      parsed.push(parsedTc)
      session.toolCalls.push(parsedTc)

      builder.addFromToolCall(parsedTc.canonicalName, tc.id, parsedTc.args)
    }

    builder.commit()
    session.instructions.push(...builder.getInstructions())

    return parsed
  }

  recordToolResult(
    sessionId: string,
    toolCallId: string,
    result: string
  ): void {
    const session = this.sessions.get(sessionId)
    if (!session) return

    for (const instr of session.instructions) {
      const content = instr.content
      if (
        typeof content === "object" &&
        content !== null &&
        "tool_call_id" in content
      ) {
        const tc = content as { tool_call_id: string; result?: string }
        if (tc.tool_call_id === toolCallId) {
          tc.result = result
          break
        }
      }
    }
  }

  async triggerOptimize(sessionId: string): Promise<SessionOptimizeResult> {
    const session = this.sessions.get(sessionId)
    if (!session) {
      return {
        sessionId,
        traceId: "",
        optimized: false,
        message: "Session not found",
      }
    }

    if (!this.optimizeEnabled) {
      return {
        sessionId,
        traceId: session.traceId,
        optimized: false,
        message: "Optimization not enabled",
      }
    }

    if (this.optimizeCallback) {
      try {
        await this.optimizeCallback(session)
        return {
          sessionId,
          traceId: session.traceId,
          optimized: true,
        }
      } catch (err) {
        return {
          sessionId,
          traceId: session.traceId,
          optimized: false,
          message: err instanceof Error ? err.message : "Optimization failed",
        }
      }
    }

    return {
      sessionId,
      traceId: session.traceId,
      optimized: false,
      message: "No optimization callback configured",
    }
  }

  setOptimizeCallback(callback: (session: OpenClawSession) => Promise<void>): void {
    this.optimizeCallback = callback
  }

  setOptimizeEnabled(enabled: boolean): void {
    this.optimizeEnabled = enabled
  }

  getAllSessions(): OpenClawSession[] {
    return Array.from(this.sessions.values())
  }

  getActiveSessions(): OpenClawSession[] {
    return Array.from(this.sessions.values()).filter(
      (s) => s.status === "running"
    )
  }

  clearCompletedSessions(): number {
    let cleared = 0
    for (const [id, session] of this.sessions) {
      if (session.status !== "running") {
        this.sessions.delete(id)
        this.traceToSession.delete(session.traceId)
        cleared++
      }
    }
    return cleared
  }

  private generateSessionId(): string {
    return `oc-session-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  }

  private generateTraceId(): string {
    return `oc-trace-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  }
}

export const openClawSessionManager = new OpenClawSessionManager()
