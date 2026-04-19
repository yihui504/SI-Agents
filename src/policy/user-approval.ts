export function applyUserApprovalPreprocessing(
  instructions: Record<string, unknown>[],
  latestInstructions: Record<string, unknown>[],
): { instructions: Record<string, unknown>[]; latestInstructions: Record<string, unknown>[] } {
  const processList = (list: Record<string, unknown>[]): Record<string, unknown>[] => {
    return list.map((ins) => {
      if (typeof ins !== "object" || ins === null) return ins
      const policyConfirmationAsk = ins.policy_confirmation_ask
      const userApproved = ins.user_approved
      if (!policyConfirmationAsk) return ins
      if (userApproved) return ins
      const out = { ...ins }
      if (out.content && typeof out.content === "object") {
        out.content = { ...(out.content as Record<string, unknown>) }
      }
      out.policy_protected = "user_approval_required"
      return out
    })
  }
  return {
    instructions: processList(instructions),
    latestInstructions: processList(latestInstructions),
  }
}
