import { z } from "zod"
import { LEVELS } from "./instruction.ts"

export const TaintLevelSchema = z.enum(LEVELS)
export type TaintLevel = z.infer<typeof TaintLevelSchema>

export const PathRuleSchema = z.object({
  pattern: z.string(),
  trustworthiness: z.enum(LEVELS).default("UNKNOWN"),
  confidentiality: z.enum(LEVELS).default("UNKNOWN"),
})
export type PathRule = z.infer<typeof PathRuleSchema>

export const TaintStateSchema = z.object({
  trace_id: z.string(),
  instructions: z.array(z.record(z.unknown())),
  current_step: z.number().default(0),
})
export type TaintState = z.infer<typeof TaintStateSchema>

export const ToolAliasMapSchema = z.record(z.string(), z.string())
export type ToolAliasMap = z.infer<typeof ToolAliasMapSchema>
