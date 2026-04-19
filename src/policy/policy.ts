import type { PolicyCheckResult } from "../types/policy.ts"

export abstract class Policy {
  abstract check(
    instructions: Record<string, unknown>[],
    currentResponse: Record<string, unknown>,
    latestInstructions: Record<string, unknown>[],
    traceId: string,
  ): Promise<PolicyCheckResult>
}
