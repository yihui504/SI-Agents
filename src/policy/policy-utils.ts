import path from "node:path"
import { LEVEL_ORDER, type Level } from "../types/instruction.ts"

export function _safeStr(v: unknown, defaultVal: string = ""): string {
  return typeof v === "string" && v.trim() ? v.trim() : defaultVal
}

export function _safeUpper(v: unknown, defaultVal: string = ""): string {
  const s = _safeStr(v, defaultVal)
  return s ? s.toUpperCase() : defaultVal
}

export function _safeLower(v: unknown, defaultVal: string = ""): string {
  const s = _safeStr(v, defaultVal)
  return s ? s.toLowerCase() : defaultVal
}

export function _safeLevel(v: unknown, defaultVal: string = "UNKNOWN"): string {
  const s = _safeUpper(v, defaultVal)
  return s in LEVEL_ORDER ? s : defaultVal
}

export function _levelRank(v: unknown): number {
  return LEVEL_ORDER[_safeLevel(v) as keyof typeof LEVEL_ORDER] ?? 0.5
}

export function _levelAtLeast(actual: unknown, required: unknown): boolean {
  return _levelRank(actual) >= _levelRank(required)
}

export function _levelMax(a: unknown, b: unknown): string {
  return _levelRank(a) >= _levelRank(b) ? _safeLevel(a) : _safeLevel(b)
}

export function _safeDict(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v)
    ? v as Record<string, unknown>
    : {}
}

export function _normList(v: unknown): string[] {
  if (Array.isArray(v)) {
    return v.filter((x): x is string => !!(typeof x === "string" && x.trim())).map((x) => x.trim())
  }
  return []
}

export function _normSet(v: unknown): Set<string> {
  return new Set(_normList(v).map((x) => x.toUpperCase()))
}

export function _softSourceConf(level: string): string {
  const lv = _safeLevel(level)
  return lv === "UNKNOWN" ? "LOW" : lv
}

export function extractToolCalls(response: Record<string, unknown>): Record<string, unknown>[] {
  const tcs = response.tool_calls
  if (Array.isArray(tcs)) {
    return tcs.filter((tc): tc is Record<string, unknown> => tc !== null && typeof tc === "object" && !Array.isArray(tc))
  }
  return []
}

export function parseToolCall(tc: Record<string, unknown>): {
  toolName: string
  toolCallId: string | null
  argsDict: Record<string, unknown>
  wasJsonStr: boolean
} {
  const toolCallId = typeof tc.id === "string" ? tc.id : null
  const fn = tc.function
  if (!fn || typeof fn !== "object" || Array.isArray(fn)) {
    return { toolName: "unknown_tool", toolCallId, argsDict: {}, wasJsonStr: false }
  }
  const func = fn as Record<string, unknown>
  const nameRaw = func.name
  const toolName = typeof nameRaw === "string" && nameRaw.trim() ? nameRaw.trim() : "unknown_tool"

  const rawArgs = func.arguments
  if (typeof rawArgs === "string") {
    try {
      const parsed = JSON.parse(rawArgs)
      const argsDict = typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {}
      return { toolName, toolCallId, argsDict, wasJsonStr: true }
    } catch {
      return { toolName, toolCallId, argsDict: {}, wasJsonStr: true }
    }
  }
  if (rawArgs !== null && typeof rawArgs === "object" && !Array.isArray(rawArgs)) {
    const argsDict = { ...(rawArgs as Record<string, unknown>) }
    return { toolName, toolCallId, argsDict, wasJsonStr: false }
  }
  return { toolName, toolCallId, argsDict: {}, wasJsonStr: false }
}

export function writeBackToolArgs(tc: Record<string, unknown>, args: Record<string, unknown>, wasJsonStr: boolean): Record<string, unknown> {
  const out = { ...tc }
  const fn = out.function
  if (!fn || typeof fn !== "object" || Array.isArray(fn)) return out
  const fn2 = { ...(fn as Record<string, unknown>) }
  if (wasJsonStr) {
    fn2.arguments = JSON.stringify(args)
  } else {
    fn2.arguments = args
  }
  out.function = fn2
  return out
}

export function _appendUniqueError(errors: string[], seen: Set<string>, message: string): void {
  if (!seen.has(message)) {
    errors.push(message)
    seen.add(message)
  }
}

export function _getPrimaryPathHint(argsDict: Record<string, unknown>): string {
  for (const key of ["path", "file_path", "target_path", "destination_path", "dest_path", "output_path", "path_out", "dst"]) {
    const val = argsDict[key]
    if (typeof val === "string" && val.trim()) return val.trim()
  }
  return ""
}

export function _extractInstructionSecurity(ins: Record<string, unknown>): Record<string, unknown> {
  const st = ins !== null && typeof ins === "object" && !Array.isArray(ins) ? ins.security_type : {}
  const stDict = st !== null && typeof st === "object" && !Array.isArray(st) ? st as Record<string, unknown> : {}
  const custom = stDict.custom
  const customDict = custom !== null && typeof custom === "object" && !Array.isArray(custom) ? custom as Record<string, unknown> : {}

  return {
    instruction_type: _safeUpper(ins.instruction_type),
    instruction_category: _safeStr(ins.instruction_category),
    trustworthiness: _safeLevel(stDict.trustworthiness),
    confidentiality: _safeLevel(stDict.confidentiality),
    prop_confidentiality: _safeLevel(stDict.prop_confidentiality || stDict.confidentiality),
    prop_trustworthiness: _safeLevel(stDict.prop_trustworthiness || stDict.trustworthiness),
    authority: _safeUpper(stDict.authority, "UNKNOWN"),
    confidence: _safeLevel(stDict.confidence),
    reversible: !!stDict.reversible,
    risk: _safeUpper(stDict.risk, "UNKNOWN"),
    custom: customDict,
  }
}

export function _sourceLevels(
  sec: Record<string, unknown>,
  currentTaintStatus: Record<string, unknown> | null = null,
): [Level, Level] {
  const taintStatus = currentTaintStatus || _safeDict(sec.taint_status)
  const rawTrust = taintStatus?.source_trustworthiness
  const rawConf = taintStatus?.source_confidentiality
  const sourceTrust = rawTrust != null ? _safeLevel(rawTrust) : _safeLevel(sec.trustworthiness)
  const sourceConf = rawConf != null ? _safeLevel(rawConf) : _safeLevel(sec.confidentiality)
  return [sourceTrust as Level, sourceConf as Level]
}

export const DEFAULT_RULE_DETAILS_URL = "http://43.161.233.143:5173/"
