import { LEVEL_ORDER, type Level } from "../types/instruction.ts"
import { extractToolCalls } from "../policy/policy-utils.ts"

function safeLevel(v: unknown): Level {
  if (typeof v === "string" && v.trim() in LEVEL_ORDER) return v.trim() as Level
  return "UNKNOWN"
}

function stricterLevel(a: Level, b: Level): Level {
  return LEVEL_ORDER[a] >= LEVEL_ORDER[b] ? a : b
}

function weakerLevel(a: Level, b: Level): Level {
  return LEVEL_ORDER[a] <= LEVEL_ORDER[b] ? a : b
}

export interface PropTaintResult {
  prop_trustworthiness: Level
  prop_confidentiality: Level
}

export function computePropTaintForInstruction(
  instructions: Record<string, unknown>[],
  indexOrInstr: number | Record<string, unknown>,
  toolCallIdIndex?: Map<string, number>,
): PropTaintResult {
  let index: number
  let instr: Record<string, unknown>
  if (typeof indexOrInstr === "number") {
    index = indexOrInstr
    instr = instructions[index]
  } else {
    instr = indexOrInstr
    index = instructions.indexOf(instr)
  }
  if (!instr) {
    return { prop_trustworthiness: "UNKNOWN", prop_confidentiality: "UNKNOWN" }
  }
  const st = instr["security_type"]
  if (typeof st !== "object" || st === null) {
    return { prop_trustworthiness: "UNKNOWN", prop_confidentiality: "UNKNOWN" }
  }

  const sec = st as Record<string, unknown>
  const ownConf = safeLevel(sec["confidentiality"])
  const ownTrust = safeLevel(sec["trustworthiness"])

  const content = instr["content"]
  if (typeof content !== "object" || content === null || !("tool_name" in content)) {
    return {
      prop_trustworthiness: ownTrust,
      prop_confidentiality: ownConf,
    }
  }

  const ct = content as Record<string, unknown>
  const tcId = typeof ct["tool_call_id"] === "string" ? ct["tool_call_id"].trim() : ""
  const args = ct["arguments"]
  const refIds: string[] = []
  if (typeof args === "object" && args !== null) {
    const ref = (args as Record<string, unknown>)["reference_tool_id"]
    if (Array.isArray(ref)) {
      for (const r of ref) {
        if (typeof r === "string" && r.trim()) refIds.push(r.trim())
      }
    }
  }

  const idsToInclude = new Set<string>()
  if (tcId) idsToInclude.add(tcId)
  for (const r of refIds) idsToInclude.add(r)

  let propTrust = ownTrust
  let propConf = ownConf

  if (toolCallIdIndex) {
    const seen = new Set<number>()
    for (const id of idsToInclude) {
      const idx = toolCallIdIndex.get(id)
      if (idx !== undefined && idx !== index && !seen.has(idx)) {
        seen.add(idx)
        const other = instructions[idx]
        const ost = other["security_type"]
        if (typeof ost !== "object" || ost === null) continue
        const ostRec = ost as Record<string, unknown>
        const otherPropConf = safeLevel(ostRec["prop_confidentiality"] ?? ostRec["confidentiality"])
        const otherPropTrust = safeLevel(ostRec["prop_trustworthiness"] ?? ostRec["trustworthiness"])
        propTrust = weakerLevel(propTrust, otherPropTrust)
        propConf = stricterLevel(propConf, otherPropConf)
      }
    }
  } else {
    for (const other of instructions) {
      if (other === instr) continue
      const oc = other["content"]
      if (typeof oc !== "object" || oc === null) continue
      const oTc = (oc as Record<string, unknown>)["tool_call_id"]
      if (typeof oTc !== "string" || !idsToInclude.has(oTc.trim())) continue

      const ost = other["security_type"]
      if (typeof ost !== "object" || ost === null) continue
      const ostRec = ost as Record<string, unknown>
      const otherPropConf = safeLevel(ostRec["prop_confidentiality"] ?? ostRec["confidentiality"])
      const otherPropTrust = safeLevel(ostRec["prop_trustworthiness"] ?? ostRec["trustworthiness"])

      propTrust = weakerLevel(propTrust, otherPropTrust)
      propConf = stricterLevel(propConf, otherPropConf)
    }
  }

  return {
    prop_trustworthiness: propTrust,
    prop_confidentiality: propConf,
  }
}

export function computePropTaint(
  instructions: Record<string, unknown>[],
): void {
  const toolCallIdIndex = new Map<string, number>()
  for (let i = 0; i < instructions.length; i++) {
    const tcs = extractToolCalls(instructions[i])
    for (const tc of tcs) {
      const id = typeof tc.id === "string" ? tc.id : null
      if (id) toolCallIdIndex.set(id, i)
    }
    const content = instructions[i]["content"]
    if (typeof content === "object" && content !== null) {
      const tcId = (content as Record<string, unknown>)["tool_call_id"]
      if (typeof tcId === "string" && tcId.trim()) {
        toolCallIdIndex.set(tcId.trim(), i)
      }
    }
  }

  const visited = new Set<number>()

  function resolve(index: number): void {
    if (visited.has(index)) return
    visited.add(index)

    const instr = instructions[index]
    if (!instr) return

    const st = instr["security_type"]
    if (typeof st !== "object" || st === null) return
    const sec = st as Record<string, unknown>

    const content = instr["content"]
    if (typeof content === "object" && content !== null && "tool_name" in content) {
      const ct = content as Record<string, unknown>
      const tcId = typeof ct["tool_call_id"] === "string" ? ct["tool_call_id"].trim() : ""
      if (tcId) {
        const tcIdx = toolCallIdIndex.get(tcId)
        if (tcIdx !== undefined && !visited.has(tcIdx)) {
          resolve(tcIdx)
        }
      }
      const args = ct["arguments"]
      if (typeof args === "object" && args !== null) {
        const ref = (args as Record<string, unknown>)["reference_tool_id"]
        if (Array.isArray(ref)) {
          for (const r of ref) {
            if (typeof r !== "string") continue
            const refId = r.trim()
            const refIndex = toolCallIdIndex.get(refId)
            if (refIndex !== undefined && !visited.has(refIndex)) {
              resolve(refIndex)
            }
          }
        }
      }
    }

    const result = computePropTaintForInstruction(instructions, index, toolCallIdIndex)
    sec["prop_confidentiality"] = result.prop_confidentiality
    sec["prop_trustworthiness"] = result.prop_trustworthiness
  }

  for (let i = 0; i < instructions.length; i++) {
    resolve(i)
  }
}
