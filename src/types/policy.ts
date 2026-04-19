import { z } from "zod"

export const PolicyCheckResultSchema = z.object({
  modified: z.boolean(),
  response: z.record(z.unknown()),
  error_type: z.string().nullable(),
  policy_names: z.array(z.string()).default([]),
  policy_sources: z.record(z.string()).default({}),
  inactivate_error_type: z.string().nullable(),
})
export type PolicyCheckResult = z.infer<typeof PolicyCheckResultSchema>

export const RuleDecisionSchema = z.object({
  index: z.number(),
  rule_id: z.string(),
  title: z.string(),
  description: z.string(),
  effect: z.enum(["BLOCK", "ALLOW", "REQUIRE_APPROVAL"]),
  scope: z.string(),
  message: z.string(),
  predicate: z.unknown(),
  selector: z.record(z.unknown()),
  actual: z.record(z.unknown()),
  source: z.string().default(""),
})
export type RuleDecision = z.infer<typeof RuleDecisionSchema>

export const FlowKind = z.enum([
  "read_external", "read_sensitive", "read_state",
  "write_local", "write_shared",
  "delegate_sink", "comm_sink", "voice_sink",
  "ui_side_effect", "exec_side_effect", "persist_side_effect",
  "respond_sink", "none",
])
export type FlowKind = z.infer<typeof FlowKind>

export const PolicyRegistryEntrySchema = z.object({
  name: z.string(),
  class_path: z.string(),
  enabled: z.boolean().default(true),
  order: z.number().default(0),
})
export type PolicyRegistryEntry = z.infer<typeof PolicyRegistryEntrySchema>
