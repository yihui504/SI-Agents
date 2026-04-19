import { z } from "zod"

export interface SecurityBaseline {
  toolCalls: string[]
  pathPatterns: string[]
  taintFlows: { source: string; sink: string }[]
  riskLevel: "low" | "medium" | "high"
}

export interface SecurityConstraint {
  forbiddenTools: string[]
  forbiddenPaths: string[]
  requiredTaintRules: string[]
  maxRiskLevel: "low" | "medium" | "high"
}

export interface OptimizeRound {
  round: number
  score: number
  changes: string[]
  securityAuditResult: "passed" | "blocked" | "warning"
  securityRisks: string[]
}

export interface OptimizeConfig {
  skillId: string
  skillDir: string
  targetModel: string
  optimizerModel: string
  rounds: number
  runsPerTask: number
  securityConstraints?: SecurityConstraint
}

export interface OptimizeResult {
  proposalId: string
  bestRound: number
  rounds: OptimizeRound[]
  finalScore: number
  securityApproved: boolean
}

export const SecurityBaselineSchema = z.object({
  toolCalls: z.array(z.string()),
  pathPatterns: z.array(z.string()),
  taintFlows: z.array(z.object({
    source: z.string(),
    sink: z.string(),
  })),
  riskLevel: z.enum(["low", "medium", "high"]),
})

export const SecurityConstraintSchema = z.object({
  forbiddenTools: z.array(z.string()),
  forbiddenPaths: z.array(z.string()),
  requiredTaintRules: z.array(z.string()),
  maxRiskLevel: z.enum(["low", "medium", "high"]),
})

export const OptimizeRoundSchema = z.object({
  round: z.number(),
  score: z.number(),
  changes: z.array(z.string()),
  securityAuditResult: z.enum(["passed", "blocked", "warning"]),
  securityRisks: z.array(z.string()),
})

export const OptimizeConfigSchema = z.object({
  skillId: z.string(),
  skillDir: z.string(),
  targetModel: z.string(),
  optimizerModel: z.string(),
  rounds: z.number().default(3),
  runsPerTask: z.number().default(1),
  securityConstraints: SecurityConstraintSchema.optional(),
})

export const OptimizeResultSchema = z.object({
  proposalId: z.string(),
  bestRound: z.number(),
  rounds: z.array(OptimizeRoundSchema),
  finalScore: z.number(),
  securityApproved: z.boolean(),
})

export interface OptimizeSubmission {
  rootCause?: string
  reasoning?: string
  confidence?: number
  changedFiles?: string[]
  changes?: OptimizationChange[]
  noChanges?: boolean
  securityViolations?: string[]
}

export interface OptimizationChange {
  file: string
  section?: string
  description: string
  generality: string
  linesDelta?: number
}

export const OptimizationChangeSchema = z.object({
  file: z.string(),
  section: z.string().optional(),
  description: z.string(),
  generality: z.string().default(""),
  linesDelta: z.number().optional(),
})

export const OptimizeSubmissionSchema = z.object({
  rootCause: z.string().optional(),
  reasoning: z.string().optional(),
  confidence: z.number().optional(),
  changedFiles: z.array(z.string()).optional(),
  changes: z.array(OptimizationChangeSchema).optional(),
  noChanges: z.boolean().optional(),
  securityViolations: z.array(z.string()).optional(),
})

export interface HeadlessAgentConfig {
  cwd: string
  prompt: string
  model: string
  timeoutMs?: number
}

export interface HeadlessAgentResult {
  exitCode: number
  durationMs: number
  cost: number
  tokens: { input: number; output: number }
  rawStdout: string
  rawStderr: string
}

export const RISK_LEVEL_ORDER: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
}

export function compareRiskLevel(a: string, b: string): number {
  return (RISK_LEVEL_ORDER[a] ?? 0) - (RISK_LEVEL_ORDER[b] ?? 0)
}

export const DEFAULT_FORBIDDEN_TOOLS = [
  "exec",
  "delete",
  "rm",
  "format",
  "shutdown",
  "reboot",
]

export const DEFAULT_FORBIDDEN_PATHS = [
  "/etc/passwd",
  "/etc/shadow",
  "~/.ssh/",
  "~/.gnupg/",
  "/root/",
  "/proc/",
  "/sys/",
]

export const DEFAULT_SECURITY_CONSTRAINT: SecurityConstraint = {
  forbiddenTools: DEFAULT_FORBIDDEN_TOOLS,
  forbiddenPaths: DEFAULT_FORBIDDEN_PATHS,
  requiredTaintRules: [],
  maxRiskLevel: "medium",
}
