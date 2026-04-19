import type {
  Instruction,
  SecurityType,
  InstructionType,
  InstructionCategory,
  ToolCall,
  Level,
} from "../types/instruction.ts"
import {
  parseToolInstruction,
  INSTRUCTION_TYPE_TO_CATEGORY,
} from "./tool-parsers.ts"

const TAINT_LEVEL_ORDER: Record<string, number> = {
  LOW: 0,
  MID: 5,
  UNKNOWN: 10,
  HIGH: 20,
}

function makeSecurityType(partial: Partial<SecurityType> = {}): SecurityType {
  return {
    confidentiality: partial.confidentiality ?? "UNKNOWN",
    trustworthiness: partial.trustworthiness ?? "UNKNOWN",
    prop_confidentiality: partial.prop_confidentiality ?? "UNKNOWN",
    prop_trustworthiness: partial.prop_trustworthiness ?? "UNKNOWN",
    confidence: partial.confidence ?? "UNKNOWN",
    reversible: partial.reversible ?? false,
    authority: partial.authority ?? "UNKNOWN",
    risk: partial.risk ?? "UNKNOWN",
    custom: partial.custom ?? {},
  }
}

function safeLevel(v: unknown): string {
  if (typeof v === "string" && v.trim() && v.trim() in TAINT_LEVEL_ORDER) {
    return v.trim()
  }
  return "UNKNOWN"
}

function computePropTaint(
  instructions: Instruction[],
  instr: Instruction
): { trustworthiness: string; confidentiality: string } {
  const st = instr.security_type
  if (!st) return { trustworthiness: "UNKNOWN", confidentiality: "UNKNOWN" }

  const ownConf = safeLevel(st.confidentiality)
  const ownTrust = safeLevel(st.trustworthiness)

  const content = instr.content
  if (
    typeof content !== "object" ||
    content === null ||
    !("tool_name" in content)
  ) {
    return {
      trustworthiness: ownTrust in TAINT_LEVEL_ORDER ? ownTrust : "UNKNOWN",
      confidentiality: ownConf in TAINT_LEVEL_ORDER ? ownConf : "UNKNOWN",
    }
  }

  const contentRecord = content as Record<string, unknown>
  const tcId =
    typeof contentRecord.tool_call_id === "string"
      ? contentRecord.tool_call_id.trim()
      : ""
  const args = contentRecord.arguments as Record<string, unknown> | undefined
  const refIds: string[] = Array.isArray(args?.reference_tool_id)
    ? ((args!.reference_tool_id as string[]).filter(
        (r) => typeof r === "string" && r.trim()
      ) as string[])
    : []
  const idsToInclude = new Set<string>()
  if (tcId) idsToInclude.add(tcId)
  for (const r of refIds) idsToInclude.add(r.trim())

  const trustVals: string[] = [ownTrust]
  const confVals: string[] = [ownConf]

  for (const other of instructions) {
    if (other === instr) continue
    const oc = other.content
    if (typeof oc !== "object" || oc === null) continue
    const ocRecord = oc as Record<string, unknown>
    const oTc = ocRecord.tool_call_id
    if (typeof oTc !== "string" || !idsToInclude.has(oTc.trim())) continue
    const ost = other.security_type
    if (!ost) continue
    const ostRecord = ost as Record<string, unknown>
    const propConf = ostRecord.prop_confidentiality ?? ostRecord.confidentiality
    const propTrust =
      ostRecord.prop_trustworthiness ?? ostRecord.trustworthiness
    if (typeof propConf === "string" && propConf.trim() in TAINT_LEVEL_ORDER) {
      confVals.push(propConf.trim())
    }
    if (typeof propTrust === "string" && propTrust.trim() in TAINT_LEVEL_ORDER) {
      trustVals.push(propTrust.trim())
    }
  }

  const rawTrust =
    trustVals.length > 0
      ? trustVals.reduce((a, b) =>
          TAINT_LEVEL_ORDER[a] <= TAINT_LEVEL_ORDER[b] ? a : b
        )
      : "UNKNOWN"
  const rawConf =
    confVals.length > 0
      ? confVals.reduce((a, b) =>
          TAINT_LEVEL_ORDER[a] >= TAINT_LEVEL_ORDER[b] ? a : b
        )
      : "UNKNOWN"

  return { trustworthiness: rawTrust, confidentiality: rawConf }
}

export class InstructionBuilder {
  private instructions: Instruction[] = []
  private step: number = 0
  private traceId: string
  private agent: "openclaw" | "bare_agent"
  private rootSourceMessageId: string | null = null
  private lastInstructionId: string | null = null
  private committedCount: number = 0

  constructor(traceId: string, agent: "openclaw" | "bare_agent" = "openclaw") {
    this.traceId = traceId
    this.agent = agent
  }

  private nextStep(): number {
    return this.step++
  }

  private commitInstruction(instr: Instruction): Instruction {
    if (this.rootSourceMessageId === null) {
      this.rootSourceMessageId = instr.id
    }
    if (instr.source_message_id === null) {
      instr.source_message_id = this.rootSourceMessageId
    }
    this.lastInstructionId = instr.id
    this.instructions.push(instr)

    const taint = computePropTaint(this.instructions, instr)
    instr.security_type.prop_confidentiality = taint.confidentiality as Level
    instr.security_type.prop_trustworthiness = taint.trustworthiness as Level

    return instr
  }

  addFromStructuredOutput(
    data: { category?: string; content?: string; intent?: string }
  ): Instruction {
    const actionType = data.category ?? data.intent ?? "REASON"
    const category = INSTRUCTION_TYPE_TO_CATEGORY[actionType]
    const isValidType = actionType in INSTRUCTION_TYPE_TO_CATEGORY

    const securityType = makeSecurityType({
      confidentiality: "LOW",
      trustworthiness: "HIGH",
      confidence: "UNKNOWN",
      reversible: true,
      authority: "UNKNOWN",
    })

    const instr: Instruction = {
      id: crypto.randomUUID(),
      content: { text: data.content ?? "" },
      runtime_step: this.nextStep(),
      parent_id: this.lastInstructionId,
      source_message_id: null,
      security_type: securityType,
      rule_types: [],
      instruction_category: category ?? "COGNITIVE.Reasoning",
      instruction_type: (isValidType ? actionType : "REASON") as InstructionType,
    }

    return this.commitInstruction(instr)
  }

  addFromToolCall(
    toolName: string,
    toolCallId: string,
    args: Record<string, unknown>
  ): Instruction {
    const content: ToolCall = {
      tool_name: toolName,
      tool_call_id: toolCallId,
      arguments: args,
    }

    const parsed = parseToolInstruction(toolName, args, this.agent)
    const category =
      INSTRUCTION_TYPE_TO_CATEGORY[parsed.instructionType] ??
      parsed.instructionCategory

    const instr: Instruction = {
      id: crypto.randomUUID(),
      content,
      runtime_step: this.nextStep(),
      parent_id: this.lastInstructionId,
      source_message_id: null,
      security_type: makeSecurityType(parsed.securityType),
      rule_types: [],
      instruction_category: category as InstructionCategory,
      instruction_type: parsed.instructionType,
    }

    return this.commitInstruction(instr)
  }

  mergeToolResult(toolCallId: string, result: string): void {
    for (const instr of this.instructions) {
      const content = instr.content
      if (
        typeof content === "object" &&
        content !== null &&
        "tool_call_id" in content
      ) {
        const tc = content as ToolCall
        if (tc.tool_call_id === toolCallId) {
          tc.result = result
          break
        }
      }
    }
  }

  commit(): void {
    for (const instr of this.instructions) {
      const taint = computePropTaint(this.instructions, instr)
      instr.security_type.prop_confidentiality = taint.confidentiality as Level
      instr.security_type.prop_trustworthiness = taint.trustworthiness as Level
    }
    this.committedCount = this.instructions.length
  }

  getInstructions(): Instruction[] {
    return this.instructions
  }

  getLatestInstructions(): Instruction[] {
    return this.instructions.slice(this.committedCount)
  }

  toJSON(): object {
    return {
      trace_id: this.traceId,
      created_at: new Date().toISOString(),
      instructions: this.instructions,
    }
  }
}
