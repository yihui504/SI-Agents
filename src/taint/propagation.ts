import { LEVEL_ORDER, type Level } from "../types/instruction.ts"

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
  instr: Record<string, unknown>,
): PropTaintResult {
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

  return {
    prop_trustworthiness: propTrust,
    prop_confidentiality: propConf,
  }
}

export function computePropTaint(
  instructions: Record<string, unknown>[],
): void {
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
      const args = ct["arguments"]
      if (typeof args === "object" && args !== null) {
        const ref = (args as Record<string, unknown>)["reference_tool_id"]
        if (Array.isArray(ref)) {
          for (const r of ref) {
            if (typeof r !== "string") continue
            const refId = r.trim()
            const refIndex = instructions.findIndex((other) => {
              const oc = other["content"]
              if (typeof oc !== "object" || oc === null) return false
              return (oc as Record<string, unknown>)["tool_call_id"] === refId
            })
            if (refIndex >= 0 && !visited.has(refIndex)) {
              resolve(refIndex)
            }
          }
        }
      }
    }

    const result = computePropTaintForInstruction(instructions, instr)
    sec["prop_confidentiality"] = result.prop_confidentiality
    sec["prop_trustworthiness"] = result.prop_trustworthiness
  }

  for (let i = 0; i < instructions.length; i++) {
    resolve(i)
  }
}
