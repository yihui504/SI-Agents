import type { ToolCall } from "../types/instruction.ts"

export interface PendingConfirmation {
  traceId: string
  toolCallId: string
  toolName: string
  toolArgs: Record<string, unknown>
  reason: string
  timestamp: number
}

export interface ConfirmationResult {
  traceId: string
  toolCallId: string
  approved: boolean
  timestamp: number
}

export class ConfirmationHandler {
  private pendingConfirmations: Map<string, PendingConfirmation> = new Map()
  private confirmationResults: Map<string, ConfirmationResult> = new Map()
  private waitingResolvers: Map<string, (approved: boolean) => void> = new Map()

  requestConfirmation(
    traceId: string,
    toolCallId: string,
    toolName: string,
    toolArgs: Record<string, unknown>,
    reason: string,
  ): Promise<boolean> {
    const confirmation: PendingConfirmation = {
      traceId,
      toolCallId,
      toolName,
      toolArgs,
      reason,
      timestamp: Date.now(),
    }

    this.pendingConfirmations.set(toolCallId, confirmation)

    return new Promise((resolve) => {
      this.waitingResolvers.set(toolCallId, resolve)
    })
  }

  handleConfirmation(traceId: string, toolCallId: string, reply: "yes" | "no"): void {
    const pending = this.pendingConfirmations.get(toolCallId)
    if (!pending || pending.traceId !== traceId) return

    const approved = reply === "yes"

    const result: ConfirmationResult = {
      traceId,
      toolCallId,
      approved,
      timestamp: Date.now(),
    }
    this.confirmationResults.set(toolCallId, result)
    this.pendingConfirmations.delete(toolCallId)

    const resolver = this.waitingResolvers.get(toolCallId)
    if (resolver) {
      resolver(approved)
      this.waitingResolvers.delete(toolCallId)
    }
  }

  hasPendingConfirmation(traceId: string): boolean {
    for (const pending of this.pendingConfirmations.values()) {
      if (pending.traceId === traceId) return true
    }
    return false
  }

  getPendingConfirmation(traceId: string): PendingConfirmation | null {
    for (const pending of this.pendingConfirmations.values()) {
      if (pending.traceId === traceId) return pending
    }
    return null
  }

  getAllPendingConfirmations(traceId: string): PendingConfirmation[] {
    const result: PendingConfirmation[] = []
    for (const pending of this.pendingConfirmations.values()) {
      if (pending.traceId === traceId) result.push(pending)
    }
    return result
  }

  getConfirmationResult(toolCallId: string): ConfirmationResult | null {
    return this.confirmationResults.get(toolCallId) ?? null
  }

  markApproved(traceId: string, toolCallId: string): void {
    this.handleConfirmation(traceId, toolCallId, "yes")
  }

  markRejected(traceId: string, toolCallId: string): void {
    this.handleConfirmation(traceId, toolCallId, "no")
  }

  cancelConfirmation(toolCallId: string): void {
    this.pendingConfirmations.delete(toolCallId)
    this.waitingResolvers.delete(toolCallId)
  }

  clearTrace(traceId: string): void {
    for (const [id, pending] of this.pendingConfirmations) {
      if (pending.traceId === traceId) {
        this.pendingConfirmations.delete(id)
        this.waitingResolvers.delete(id)
      }
    }
    for (const [id, result] of this.confirmationResults) {
      if (result.traceId === traceId) {
        this.confirmationResults.delete(id)
      }
    }
  }

  clear(): void {
    this.pendingConfirmations.clear()
    this.confirmationResults.clear()
    this.waitingResolvers.clear()
  }
}

export const confirmationHandler = new ConfirmationHandler()
