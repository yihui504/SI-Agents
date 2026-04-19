import { z } from "zod"

export const LEVELS = ["LOW", "MID", "HIGH", "UNKNOWN"] as const
export type Level = (typeof LEVELS)[number]
export const LEVEL_ORDER: Record<Level, number> = { LOW: 1, MID: 2, HIGH: 3, UNKNOWN: 0 }

export const SecurityTypeSchema = z.object({
  confidentiality: z.enum(LEVELS).default("UNKNOWN"),
  trustworthiness: z.enum(LEVELS).default("UNKNOWN"),
  prop_confidentiality: z.enum(LEVELS).default("UNKNOWN"),
  prop_trustworthiness: z.enum(LEVELS).default("UNKNOWN"),
  confidence: z.enum(LEVELS).default("UNKNOWN"),
  reversible: z.boolean().default(false),
  authority: z.string().default("UNKNOWN"),
  risk: z.enum([...LEVELS, "CRITICAL"] as const).default("UNKNOWN"),
  custom: z.record(z.unknown()).default({}),
})
export type SecurityType = z.infer<typeof SecurityTypeSchema>

export const InstructionType = z.enum([
  "REASON", "PLAN", "CRITIQUE",
  "STORE", "RETRIEVE", "COMPRESS", "PRUNE",
  "READ", "WRITE", "EXEC", "WAIT",
  "ASK", "RESPOND", "USER_MESSAGE",
  "HANDOFF", "SUBSCRIBE", "RECEIVE", "DELEGATE",
])
export type InstructionType = z.infer<typeof InstructionType>

export const InstructionCategory = z.enum([
  "COGNITIVE.Reasoning",
  "MEMORY.Management",
  "EXECUTION.Env",
  "EXECUTION.Human",
  "EXECUTION.Agent",
  "EXECUTION.Perception",
])
export type InstructionCategory = z.infer<typeof InstructionCategory>

export const ToolCallSchema = z.object({
  tool_name: z.string(),
  tool_call_id: z.string(),
  arguments: z.record(z.unknown()),
  result: z.string().optional(),
})
export type ToolCall = z.infer<typeof ToolCallSchema>

export const InstructionSchema = z.object({
  id: z.string().uuid(),
  content: z.union([
    ToolCallSchema,
    z.record(z.unknown()),
  ]),
  runtime_step: z.number().int().nonnegative(),
  parent_id: z.string().uuid().nullable(),
  source_message_id: z.string().uuid().nullable(),
  security_type: SecurityTypeSchema,
  rule_types: z.array(z.string()).default([]),
  instruction_category: InstructionCategory,
  instruction_type: InstructionType,
  policy_protected: z.string().optional(),
  policy_confirmation_ask: z.boolean().optional(),
  user_approved: z.boolean().optional(),
})
export type Instruction = z.infer<typeof InstructionSchema>
