import path from "node:path"
import { mkdir, readFile, writeFile } from "node:fs/promises"
import type { BoostCandidate, SolidificationState, SolidificationStateFile, SolidificationEntry } from "./types.ts"
import { BoostCandidatesFileSchema, SolidificationStateFileSchema } from "./types.ts"

function getJitBoostDir(skillId: string): string {
  const homeDir = process.env.HOME || process.env.USERPROFILE || ""
  return path.join(homeDir, ".skvm", "proposals", "jit-boost", skillId)
}

function candidatesPath(skillId: string): string {
  return path.join(getJitBoostDir(skillId), "boost-candidates.json")
}

function statePath(skillId: string): string {
  return path.join(getJitBoostDir(skillId), "solidification-state.json")
}

export async function loadBoostCandidates(skillId: string): Promise<BoostCandidate[]> {
  const filePath = candidatesPath(skillId)
  try {
    const raw = await readFile(filePath, "utf-8")
    const parsed = BoostCandidatesFileSchema.parse(JSON.parse(raw))
    return parsed.candidates
  } catch {
    return []
  }
}

export async function saveBoostCandidates(skillId: string, candidates: BoostCandidate[]): Promise<void> {
  const dir = getJitBoostDir(skillId)
  await mkdir(dir, { recursive: true })
  const data = BoostCandidatesFileSchema.parse({ candidates })
  await writeFile(candidatesPath(skillId), JSON.stringify(data, null, 2))
}

export async function loadSolidificationState(skillId: string): Promise<Map<string, SolidificationState>> {
  const filePath = statePath(skillId)
  try {
    const raw = await readFile(filePath, "utf-8")
    const parsed = SolidificationStateFileSchema.parse(JSON.parse(raw))
    const map = new Map<string, SolidificationState>()
    for (const entry of parsed.entries) {
      map.set(entry.candidate.id, entry.state)
    }
    return map
  } catch {
    return new Map()
  }
}

export async function saveSolidificationState(
  skillId: string,
  state: Map<string, SolidificationState>,
  candidates: BoostCandidate[],
): Promise<void> {
  const dir = getJitBoostDir(skillId)
  await mkdir(dir, { recursive: true })
  const entries: SolidificationEntry[] = []
  for (const c of candidates) {
    const s = state.get(c.id)
    if (s) {
      entries.push({ candidate: c, state: s })
    }
  }
  const data: SolidificationStateFile = {
    skillId,
    entries,
    updatedAt: new Date().toISOString(),
  }
  const validated = SolidificationStateFileSchema.parse(data)
  await writeFile(statePath(skillId), JSON.stringify(validated, null, 2))
}
