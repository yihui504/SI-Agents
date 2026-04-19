export * from "./types.ts"
export * from "./persistence.ts"
export * from "./security-audit.ts"
export * from "./solidifier.ts"

import type { RuntimeHooks } from "../types/hooks.ts"
import type { BoostCandidate, SolidificationState, BoostStats } from "./types.ts"
import type { SolidifierConfig } from "./solidifier.ts"
import { Solidifier } from "./solidifier.ts"
import { loadBoostCandidates, loadSolidificationState, saveSolidificationState } from "./persistence.ts"

export async function createBoostHooks(config: SolidifierConfig): Promise<{
  hooks: RuntimeHooks
  exportState: () => Map<string, SolidificationState>
  getStats: () => BoostStats
  saveState: () => Promise<void>
}> {
  const candidates = await loadBoostCandidates(config.skillId)
  const savedState = await loadSolidificationState(config.skillId)

  const solidifier = new Solidifier(config, candidates, savedState)

  const hooks: RuntimeHooks = {
    beforeLLM: [solidifier.createBeforeLLMHook()],
    afterLLM: [solidifier.createAfterLLMHook()],
  }

  return {
    hooks,
    exportState: () => solidifier.exportState(),
    getStats: () => solidifier.getStats(),
    saveState: async () => {
      await saveSolidificationState(config.skillId, solidifier.exportState(), candidates)
    },
  }
}
