import type { PolicyCheckResult } from "../types/policy.ts"
import type { Policy } from "./policy.ts"
import { PolicyRegistry } from "./registry.ts"
import { applyPolicyEnforcementMode } from "./enforcement-mode.ts"
import { applyUserApprovalPreprocessing } from "./user-approval.ts"

export function checkResponsePolicy(
  traceId: string,
  instructions: Record<string, unknown>[],
  currentResponse: Record<string, unknown>,
  latestInstructions: Record<string, unknown>[],
  registry: PolicyRegistry,
): Promise<PolicyCheckResult> {
  const { instructions: processedInstructions, latestInstructions: processedLatest } =
    applyUserApprovalPreprocessing(instructions, latestInstructions || [])

  const entries = registry.getEntries()
  let response = currentResponse
  const errors: string[] = []
  const inactivateErrors: string[] = []
  const policyNames: string[] = []
  const policySources: Record<string, string> = {}

  const runPolicies = async (): Promise<PolicyCheckResult> => {
    for (const entry of entries) {
      const policy = registry.getAllPolicies().find((_, i) => registry.getEntries()[i]?.name === entry.name)
      if (!policy) continue

      const responseBefore = structuredClone(response)
      const result = await policy.check(
        processedInstructions,
        response,
        processedLatest,
        traceId,
      )

      const enforcedResult = applyPolicyEnforcementMode(entry.enabled, responseBefore, result)

      if (enforcedResult.modified) {
        response = enforcedResult.response
        if (enforcedResult.error_type) {
          errors.push(enforcedResult.error_type)
        }
        if (!policySources[entry.name]) {
          policyNames.push(entry.name)
          policySources[entry.name] = entry.class_path
        }
      }

      if (enforcedResult.inactivate_error_type) {
        inactivateErrors.push(enforcedResult.inactivate_error_type)
      }
    }

    return {
      modified: errors.length > 0,
      response,
      error_type: errors.length > 0 ? errors.join("\n") : null,
      policy_names: policyNames,
      policy_sources: policySources,
      inactivate_error_type: inactivateErrors.length > 0 ? inactivateErrors.join("\n") : null,
    }
  }

  return runPolicies()
}
