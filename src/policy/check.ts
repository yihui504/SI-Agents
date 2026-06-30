import type { PolicyCheckResult } from "../types/policy.ts"
import type { Policy } from "./policy.ts"
import { PolicyRegistry } from "./registry.ts"
import { applyPolicyEnforcementMode } from "./enforcement-mode.ts"
import { applyUserApprovalPreprocessing } from "./user-approval.ts"
import { InstructionSchema } from "../types/instruction.ts"
import { NanobotPolicy } from "./nanobot.ts"
import { UnaryGatePolicy } from "./unary-gate.ts"
import { RelationalPolicy } from "./relational.ts"
import { EFSMPolicy } from "./efsm.ts"

function validateInstructions(instructions: Record<string, unknown>[]): Record<string, unknown>[] {
  return instructions.map((instr, i) => {
    try {
      return InstructionSchema.parse(instr)
    } catch (e) {
      return instr
    }
  })
}

export function checkResponsePolicy(
  traceId: string,
  instructions: Record<string, unknown>[],
  currentResponse: Record<string, unknown>,
  latestInstructions: Record<string, unknown>[],
  registry: PolicyRegistry,
): Promise<PolicyCheckResult> {
  const validatedInstructions = validateInstructions(instructions)
  const validatedLatestInstructions = validateInstructions(latestInstructions || [])

  const { instructions: processedInstructions, latestInstructions: processedLatest } =
    applyUserApprovalPreprocessing(validatedInstructions, validatedLatestInstructions)

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

const DEFAULT_POLICY_ORDER: Record<string, number> = {
  NanobotPolicy: 10,
  UnaryGatePolicy: 20,
  RelationalPolicy: 30,
  EFSMPolicy: 40,
}

export function registerDefaultPolicies(registry: PolicyRegistry): void {
  const defaults: { name: string; class_path: string; order: number; instance: Policy }[] = [
    { name: "NanobotPolicy", class_path: "policy/nanobot", order: DEFAULT_POLICY_ORDER.NanobotPolicy, instance: new NanobotPolicy() },
    { name: "UnaryGatePolicy", class_path: "policy/unary-gate", order: DEFAULT_POLICY_ORDER.UnaryGatePolicy, instance: new UnaryGatePolicy() },
    { name: "RelationalPolicy", class_path: "policy/relational", order: DEFAULT_POLICY_ORDER.RelationalPolicy, instance: new RelationalPolicy() },
    { name: "EFSMPolicy", class_path: "policy/efsm", order: DEFAULT_POLICY_ORDER.EFSMPolicy, instance: new EFSMPolicy() },
  ]

  for (const { name, class_path, order, instance } of defaults) {
    const existing = registry.getEntry(name)
    if (existing) {
      if (existing.order === undefined || existing.order === 0) {
        existing.order = order
      }
    } else {
      registry.register({ name, class_path, enabled: true, order }, instance)
    }
  }
}
