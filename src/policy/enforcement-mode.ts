import type { PolicyCheckResult } from "../types/policy.ts"

export function applyPolicyEnforcementMode(
  enforce: boolean,
  responseBefore: Record<string, unknown>,
  result: PolicyCheckResult,
): PolicyCheckResult {
  if (enforce) {
    return result
  }
  if (!result.modified) {
    return result
  }
  const msg = (result.error_type || "").trim() || "policy would have modified the response"
  return {
    modified: false,
    response: structuredClone(responseBefore),
    error_type: null,
    inactivate_error_type: msg,
    policy_names: result.policy_names,
    policy_sources: result.policy_sources,
  }
}
