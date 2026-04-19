import { z } from "zod"

export const ParamDefSchema = z.object({
  type: z.enum(["string", "number"]),
  description: z.string(),
  extractPattern: z.string().optional(),
})

export type ParamDef = z.infer<typeof ParamDefSchema>

export const ParamValueSchema = z.union([z.string(), ParamDefSchema])

export function normalizeParamDef(paramName: string, value: string | ParamDef): ParamDef {
  if (typeof value === "string") {
    return { type: value as "string" | "number", description: paramName }
  }
  return value
}

export const BoostCandidateSchema = z.object({
  id: z.string(),
  skillId: z.string(),
  keywords: z.array(z.string()).min(1),
  codeSignature: z.string(),
  functionTemplate: z.string(),
  params: z.record(ParamValueSchema),
  materializationType: z.enum(["shell", "python"]).optional(),
  monitoredTools: z.array(z.string()).optional(),
  createdAt: z.number().default(() => Date.now()),
})

export type BoostCandidate = z.infer<typeof BoostCandidateSchema>

export const SolidificationStateSchema = z.object({
  candidateId: z.string(),
  matchCount: z.number().default(0),
  fallbackCount: z.number().default(0),
  promoted: z.boolean().default(false),
  lastMatch: z.number().default(0),
})

export type SolidificationState = z.infer<typeof SolidificationStateSchema>

export const SolidificationEntrySchema = z.object({
  candidate: BoostCandidateSchema,
  state: SolidificationStateSchema,
  promotedAt: z.string().optional(),
})

export type SolidificationEntry = z.infer<typeof SolidificationEntrySchema>

export const SolidificationStateFileSchema = z.object({
  skillId: z.string(),
  entries: z.array(SolidificationEntrySchema),
  updatedAt: z.string(),
})

export type SolidificationStateFile = z.infer<typeof SolidificationStateFileSchema>

export const BoostCandidatesFileSchema = z.object({
  candidates: z.array(BoostCandidateSchema),
})

export type BoostCandidatesFile = z.infer<typeof BoostCandidatesFileSchema>

export interface BoostStats {
  totalCandidates: number
  promotedCount: number
  totalMatches: number
  totalFallbacks: number
  candidates: {
    id: string
    promoted: boolean
    matchCount: number
    fallbackCount: number
  }[]
}

export interface SecurityAuditResult {
  passed: boolean
  reason?: string
  blockedRules?: string[]
  warnings?: string[]
}

export interface ExtractionResult {
  params: Record<string, string>
  complete: boolean
  method: "regex" | "llm" | "none"
}
