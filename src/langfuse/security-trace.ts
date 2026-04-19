import type { LangfuseClient } from "./client.ts"

export interface SecurityEvent {
  policyName: string
  violationType: string
  blockReason: string
  userConfirmation?: "yes" | "no"
  toolName?: string
  instructionType?: string
}

export interface TaintPropagationEvent {
  toolName: string
  taintLevel: {
    trustworthiness: string
    confidentiality: string
  }
}

export class SecurityTraceEmitter {
  private client: LangfuseClient
  private traceId: string
  private activeSpans: Map<string, string> = new Map()

  constructor(client: LangfuseClient, traceId: string) {
    this.client = client
    this.traceId = traceId
  }

  async emitPolicyBlock(event: SecurityEvent): Promise<void> {
    const spanId = await this.client.createSpan({
      traceId: this.traceId,
      name: `policy-block-${event.policyName}`,
      type: "security",
      metadata: {
        eventType: "policy_block",
        policyName: event.policyName,
        violationType: event.violationType,
        blockReason: event.blockReason,
        toolName: event.toolName,
        instructionType: event.instructionType,
        timestamp: new Date().toISOString(),
      },
    })

    this.activeSpans.set(`block-${event.policyName}`, spanId)
    await this.client.endSpan(spanId, { status: "blocked" })
  }

  async emitPolicyModify(event: SecurityEvent): Promise<void> {
    const spanId = await this.client.createSpan({
      traceId: this.traceId,
      name: `policy-modify-${event.policyName}`,
      type: "security",
      metadata: {
        eventType: "policy_modify",
        policyName: event.policyName,
        violationType: event.violationType,
        blockReason: event.blockReason,
        toolName: event.toolName,
        instructionType: event.instructionType,
        timestamp: new Date().toISOString(),
      },
    })

    this.activeSpans.set(`modify-${event.policyName}`, spanId)
    await this.client.endSpan(spanId, { status: "modified" })
  }

  async emitUserConfirmation(decision: "yes" | "no", reason: string): Promise<void> {
    await this.client.createEvent({
      traceId: this.traceId,
      name: "user-confirmation",
      metadata: {
        eventType: "user_confirmation",
        decision,
        reason,
        timestamp: new Date().toISOString(),
      },
    })
  }

  async emitTaintPropagation(event: TaintPropagationEvent): Promise<void> {
    const spanId = await this.client.createSpan({
      traceId: this.traceId,
      name: `taint-propagation-${event.toolName}`,
      type: "tool",
      metadata: {
        eventType: "taint_propagation",
        toolName: event.toolName,
        taintLevel: event.taintLevel,
        timestamp: new Date().toISOString(),
      },
    })

    this.activeSpans.set(`taint-${event.toolName}`, spanId)
    await this.client.endSpan(spanId, { status: "tracked" })
  }

  async emitPolicyCheck(params: {
    policyName: string
    checkType: "pre" | "post"
    result: "passed" | "blocked" | "modified"
    details?: Record<string, unknown>
  }): Promise<void> {
    await this.client.createEvent({
      traceId: this.traceId,
      name: `policy-check-${params.policyName}`,
      metadata: {
        eventType: "policy_check",
        policyName: params.policyName,
        checkType: params.checkType,
        result: params.result,
        details: params.details,
        timestamp: new Date().toISOString(),
      },
    })
  }

  async emitSecurityAudit(params: {
    auditType: "jit-boost" | "jit-optimize" | "tool-execution"
    result: "passed" | "blocked" | "warning"
    risks?: string[]
  }): Promise<void> {
    const spanId = await this.client.createSpan({
      traceId: this.traceId,
      name: `security-audit-${params.auditType}`,
      type: "security",
      metadata: {
        eventType: "security_audit",
        auditType: params.auditType,
        result: params.result,
        risks: params.risks || [],
        timestamp: new Date().toISOString(),
      },
    })

    await this.client.endSpan(spanId, { auditComplete: true })
  }

  getTraceId(): string {
    return this.traceId
  }
}
