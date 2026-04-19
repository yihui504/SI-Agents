import { SkillOptimizer } from "./optimizer.ts"
import type { OptimizeConfig, OptimizeResult } from "./types.ts"

export {
  SecurityBaselineSchema,
  SecurityConstraintSchema,
  OptimizeRoundSchema,
  OptimizeConfigSchema,
  OptimizeResultSchema,
  OptimizationChangeSchema,
  OptimizeSubmissionSchema,
  RISK_LEVEL_ORDER,
  DEFAULT_FORBIDDEN_TOOLS,
  DEFAULT_FORBIDDEN_PATHS,
  DEFAULT_SECURITY_CONSTRAINT,
  compareRiskLevel,
} from "./types.ts"

export type {
  SecurityBaseline,
  SecurityConstraint,
  OptimizeRound,
  OptimizeConfig,
  OptimizeResult,
  OptimizeSubmission,
  OptimizationChange,
  HeadlessAgentConfig,
  HeadlessAgentResult,
} from "./types.ts"

export { SkillSecurityScanner } from "./scanner.ts"
export { SecurityConstraintInjector } from "./constraints.ts"
export { OptimizeSecurityVerifier, type VerifyResult } from "./verifier.ts"
export { SkillOptimizer }
export {
  OptimizationLoop,
  createOptimizationLoop,
  DEFAULT_LOOP_CONFIG,
  type OptimizationLoopConfig,
  type IOptimizer,
  type RoundResult,
} from "./loop.ts"
export { WorkspaceManager, withWorkspace, type WorkspaceConfig } from "./workspace.ts"
export { RunStatus, RunStatusManager } from "./run-status.ts"
export type { RunInfo } from "./run-status.ts"

export async function jitOptimize(
  config: OptimizeConfig,
): Promise<OptimizeResult> {
  const optimizer = new SkillOptimizer(config)
  return optimizer.optimize()
}
