import type { PolicyCheckResult } from "../types/policy.ts"

export interface PolicyCheckContext {
  instructions: Record<string, unknown>[]
  currentResponse: Record<string, unknown>
  latestInstructions: Record<string, unknown>[]
  traceId: string
}

export abstract class Policy {
  abstract check(
    instructions: Record<string, unknown>[],
    currentResponse: Record<string, unknown>,
    latestInstructions: Record<string, unknown>[],
    traceId: string,
  ): Promise<PolicyCheckResult>
}
