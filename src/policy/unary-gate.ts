import path from "node:path"
import type { PolicyCheckResult, RuleDecision } from "../types/policy.ts"
import { LEVEL_ORDER } from "../types/instruction.ts"
import { Policy } from "./policy.ts"

const RULE_DETAILS_URL = "http://43.161.233.143:5173/"

const UG060_PROTECTED_BASENAMES: Set<string> = new Set(["SOUL.MD", "AGENTS.MD", "IDENTITY.MD"])

const UG063_PROTECTED_READ_PATHS: Set<string> = new Set([
  "/etc/shadow", "/etc/gshadow", "/etc/passwd",
  "/etc/ssh/sshd_config", "/etc/ssh/ssh_host_rsa_key",
  "/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_ecdsa_key",
])

function _safeStr(v: unknown, defaultVal: string = ""): string {
  return typeof v === "string" && v.trim() ? v.trim() : defaultVal
}

function _safeUpper(v: unknown, defaultVal: string = ""): string {
  const s = _safeStr(v, defaultVal)
  return s ? s.toUpperCase() : defaultVal
}

function _safeLower(v: unknown, defaultVal: string = ""): string {
  const s = _safeStr(v, defaultVal)
  return s ? s.toLowerCase() : defaultVal
}

function _safeLevel(v: unknown, defaultVal: string = "UNKNOWN"): string {
  const s = _safeUpper(v, defaultVal)
  return s in LEVEL_ORDER ? s : defaultVal
}

function _levelRank(v: unknown): number {
  return LEVEL_ORDER[_safeLevel(v) as keyof typeof LEVEL_ORDER] ?? 0.5
}

function _levelAtLeast(actual: unknown, required: unknown): boolean {
  return _levelRank(actual) >= _levelRank(required)
}

function _normList(v: unknown): string[] {
  if (Array.isArray(v)) {
    return v.filter((x): x is string => !!(typeof x === "string" && x.trim())).map((x) => x.trim())
  }
  return []
}

function _normSet(v: unknown): Set<string> {
  return new Set(_normList(v).map((x) => x.toUpperCase()))
}

function _safeDict(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v)
    ? v as Record<string, unknown>
    : {}
}

function _latestToolInstrIndex(
  latestInstructions: Record<string, unknown>[],
): Map<string, Record<string, unknown>> {
  const out = new Map<string, Record<string, unknown>>()
  for (const ins of latestInstructions || []) {
    const content = ins.content
    if (content === null || typeof content !== "object" || Array.isArray(content)) continue
    const tcid = (content as Record<string, unknown>).tool_call_id
    if (typeof tcid === "string" && tcid) {
      out.set(tcid, ins)
    }
  }
  return out
}

function _findLatestRespondInstruction(
  latestInstructions: Record<string, unknown>[],
): Record<string, unknown> | undefined {
  for (let i = (latestInstructions || []).length - 1; i >= 0; i--) {
    if (_safeUpper(latestInstructions[i].instruction_type) === "RESPOND") {
      return latestInstructions[i]
    }
  }
  return undefined
}

function _extractSecurityType(ins: Record<string, unknown>): Record<string, unknown> {
  const st = ins.security_type
  return st !== null && typeof st === "object" && !Array.isArray(st)
    ? st as Record<string, unknown>
    : {}
}

function _extractCustom(ins: Record<string, unknown>): Record<string, unknown> {
  const st = _extractSecurityType(ins)
  const custom = st.custom
  return custom !== null && typeof custom === "object" && !Array.isArray(custom)
    ? custom as Record<string, unknown>
    : {}
}

function _extractInstructionTags(ins: Record<string, unknown>): Set<string> {
  const tags = new Set<string>()
  const ruleTypes = ins.rule_types
  if (Array.isArray(ruleTypes)) {
    for (const item of ruleTypes) {
      if (typeof item === "string" && item.trim()) {
        tags.add(item.trim().toUpperCase())
      } else if (item !== null && typeof item === "object") {
        const d = item as Record<string, unknown>
        for (const k of ["name", "type", "tag", "label"]) {
          const val = d[k]
          if (typeof val === "string" && val.trim()) {
            tags.add(val.trim().toUpperCase())
          }
        }
      }
    }
  }
  const custom = _extractCustom(ins)
  for (const key of ["tags", "labels", "risk_tags"]) {
    for (const tag of _normSet(custom[key])) {
      tags.add(tag)
    }
  }
  const boolFlagToTag: Record<string, string> = {
    destructive: "DESTRUCTIVE",
    delete_like: "DELETE",
    review_required: "REVIEW_REQUIRED",
    approval_required: "APPROVAL_REQUIRED",
    high_risk: "HIGH_RISK",
    secret_like: "SECRET_LIKE",
  }
  for (const [k, tag] of Object.entries(boolFlagToTag)) {
    if (custom[k]) {
      tags.add(tag)
    }
  }
  return tags
}

function _extractMetadataView(ins: Record<string, unknown>): Record<string, unknown> {
  const st = _extractSecurityType(ins)
  const custom = _extractCustom(ins)
  return {
    instruction_type: _safeUpper(ins.instruction_type),
    instruction_category: _safeStr(ins.instruction_category),
    trustworthiness: _safeLevel(st.trustworthiness),
    confidentiality: _safeLevel(st.confidentiality),
    prop_trustworthiness: _safeLevel(st.prop_trustworthiness || st.trustworthiness),
    prop_confidentiality: _safeLevel(st.prop_confidentiality || st.confidentiality),
    confidence: _safeLevel(st.confidence),
    authority: _safeUpper(st.authority, "UNKNOWN"),
    reversible: !!st.reversible,
    risk: _safeUpper(st.risk, "UNKNOWN"),
    custom,
    tags: _extractInstructionTags(ins),
    review_required: !!custom.review_required,
    approval_required: !!custom.approval_required,
    destructive: !!(custom.destructive || custom.delete_like),
  }
}

function _estimateArgumentStringBudget(argsDict: Record<string, unknown>): number {
  let total = 0
  const stack: unknown[] = [argsDict]
  while (stack.length > 0) {
    const cur = stack.pop()!
    if (typeof cur === "string") {
      total += cur.length
    } else if (cur !== null && typeof cur === "object" && !Array.isArray(cur)) {
      stack.push(...Object.values(cur as Record<string, unknown>))
    } else if (Array.isArray(cur)) {
      stack.push(...cur)
    }
  }
  return total
}

function _mergedUnaryToolAliasMap(cfg: Record<string, unknown>): Map<string, string> {
  const merged = new Map<string, string>()
  const unaryCfg = _safeDict(cfg.unary_gate)
  const aliases = unaryCfg.tool_aliases
  if (aliases !== null && typeof aliases === "object" && !Array.isArray(aliases)) {
    for (const [k, v] of Object.entries(aliases as Record<string, unknown>)) {
      if (typeof k === "string" && k.trim() && typeof v === "string" && v.trim()) {
        merged.set(k.trim().toLowerCase(), v.trim().toLowerCase())
      }
    }
  }
  return merged
}

function _canonicalToolForUnaryGate(toolName: unknown, cfg: Record<string, unknown>): string {
  const t = (toolName ?? "").toString().trim()
  if (!t) return ""
  const key = t.toLowerCase()
  return _mergedUnaryToolAliasMap(cfg).get(key) ?? t
}

function _ensureList(v: unknown): unknown[] {
  if (Array.isArray(v)) return v
  return [v]
}

function _isValueExpr(v: unknown): boolean {
  return v !== null && typeof v === "object" && !Array.isArray(v) && ("var" in (v as Record<string, unknown>) || "const" in (v as Record<string, unknown>))
}

function _normalizeScalarForMembership(v: unknown): unknown {
  if (typeof v === "string") {
    const up = _safeUpper(v, "")
    if (up) return up
  }
  return v
}

function _compareKey(v: unknown): [number, unknown] {
  if (typeof v === "string") {
    const up = _safeUpper(v, "")
    if (up in LEVEL_ORDER) return [0, LEVEL_ORDER[up as keyof typeof LEVEL_ORDER]]
    return [1, up]
  }
  if (typeof v === "boolean") return [2, v ? 1 : 0]
  if (typeof v === "number") return [3, v]
  return [4, String(v)]
}

function _compareValues(left: unknown, right: unknown): number {
  const lk = _compareKey(left)
  const rk = _compareKey(right)
  if (lk[0] < rk[0]) return -1
  if (lk[0] > rk[0]) return 1
  const lk1 = lk[1] as number
  const rk1 = rk[1] as number
  if (lk1 < rk1) return -1
  if (lk1 > rk1) return 1
  return 0
}

function _extractVars(value: unknown): Set<string> {
  const names = new Set<string>()
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const d = value as Record<string, unknown>
    if ("var" in d && typeof d["var"] === "string") {
      names.add(d["var"] as string)
    }
    for (const v of Object.values(d)) {
      for (const name of _extractVars(v)) {
        names.add(name)
      }
    }
  } else if (Array.isArray(value)) {
    for (const item of value) {
      for (const name of _extractVars(item)) {
        names.add(name)
      }
    }
  }
  return names
}

function _resolveValue(value: unknown, ctx: Record<string, unknown>): unknown {
  if (_isValueExpr(value)) {
    const d = value as Record<string, unknown>
    if ("var" in d) return ctx[String(d["var"])]
    return d["const"]
  }
  if (Array.isArray(value)) {
    return value.map((x) => _resolveValue(x, ctx))
  }
  return value
}

function _asIterable(value: unknown): unknown[] {
  if (value instanceof Set) return [...value]
  if (Array.isArray(value)) return value
  return []
}

function _evalPredicate(pred: unknown, ctx: Record<string, unknown>): boolean {
  if (pred === null || pred === undefined) return true
  if (typeof pred === "boolean") return pred
  if (Array.isArray(pred)) return pred.every((p) => _evalPredicate(p, ctx))
  if (typeof pred !== "object") return !!pred

  if (_isValueExpr(pred)) return !!_resolveValue(pred, ctx)

  const entries = Object.entries(pred as Record<string, unknown>)
  if (entries.length !== 1) {
    return entries.every(([k, v]) => _evalPredicate({ [k]: v }, ctx))
  }

  const [op, raw] = entries[0]

  if (op === "all") return _ensureList(raw).every((p) => _evalPredicate(p, ctx))
  if (op === "any") return _ensureList(raw).some((p) => _evalPredicate(p, ctx))
  if (op === "not") return !_evalPredicate(raw, ctx)
  if (op === "truthy") return !!_resolveValue(raw, ctx)
  if (op === "falsy") return !_resolveValue(raw, ctx)
  if (op === "exists") return _resolveValue(raw, ctx) !== undefined && _resolveValue(raw, ctx) !== null
  if (op === "missing") return _resolveValue(raw, ctx) === undefined || _resolveValue(raw, ctx) === null

  const arr = _ensureList(raw)
  if (["eq", "ne", "gt", "ge", "lt", "le", "in", "not_in", "contains", "intersects"].includes(op) && arr.length !== 2) {
    return false
  }

  if (op === "eq") return _compareValues(_resolveValue(arr[0], ctx), _resolveValue(arr[1], ctx)) === 0
  if (op === "ne") return _compareValues(_resolveValue(arr[0], ctx), _resolveValue(arr[1], ctx)) !== 0
  if (op === "gt") return _compareValues(_resolveValue(arr[0], ctx), _resolveValue(arr[1], ctx)) > 0
  if (op === "ge") return _compareValues(_resolveValue(arr[0], ctx), _resolveValue(arr[1], ctx)) >= 0
  if (op === "lt") return _compareValues(_resolveValue(arr[0], ctx), _resolveValue(arr[1], ctx)) < 0
  if (op === "le") return _compareValues(_resolveValue(arr[0], ctx), _resolveValue(arr[1], ctx)) <= 0
  if (op === "in") {
    const lhs = _normalizeScalarForMembership(_resolveValue(arr[0], ctx))
    const rhs = _asIterable(_resolveValue(arr[1], ctx)).map((x) => _normalizeScalarForMembership(x))
    return rhs.includes(lhs)
  }
  if (op === "not_in") {
    const lhs = _normalizeScalarForMembership(_resolveValue(arr[0], ctx))
    const rhs = _asIterable(_resolveValue(arr[1], ctx)).map((x) => _normalizeScalarForMembership(x))
    return !rhs.includes(lhs)
  }
  if (op === "contains") {
    const container = _resolveValue(arr[0], ctx)
    const item = _normalizeScalarForMembership(_resolveValue(arr[1], ctx))
    if (container instanceof Set) {
      return [...container].some((x) => _normalizeScalarForMembership(x) === item)
    }
    if (Array.isArray(container)) {
      return container.some((x) => _normalizeScalarForMembership(x) === item)
    }
    if (typeof container === "string" && typeof item === "string") {
      return container.toUpperCase().includes(item)
    }
    return false
  }
  if (op === "intersects") {
    const left = new Set(_asIterable(_resolveValue(arr[0], ctx)).map((x) => _normalizeScalarForMembership(x)))
    const right = new Set(_asIterable(_resolveValue(arr[1], ctx)).map((x) => _normalizeScalarForMembership(x)))
    for (const l of left) {
      if (right.has(l)) return true
    }
    return false
  }

  return false
}

function _selectorValues(raw: unknown): Set<string> | null {
  if (raw === null || raw === undefined) return null
  const vals = _normSet(raw)
  return vals.size > 0 ? vals : null
}

function _selectorMatches(rule: Record<string, unknown>, ctx: Record<string, unknown>, cfg: Record<string, unknown>): boolean {
  const selector = _safeDict(rule.selector)
  const scope = _safeLower(rule.scope, "")
  if (scope && scope !== "any" && scope !== _safeLower(ctx.scope, "")) {
    return false
  }
  const toolValues = _selectorValues(selector.tool || selector.tools)
  if (toolValues && !toolValues.has("*")) {
    const raw = _safeUpper(ctx.tool_name)
    const canon = _safeUpper(_canonicalToolForUnaryGate(ctx.tool_name, cfg))
    if (!toolValues.has(raw) && !toolValues.has(canon)) {
      return false
    }
  }
  const insValues = _selectorValues(selector.instruction_type || selector.instruction_types)
  if (insValues && !insValues.has("*")) {
    const cur = _safeUpper(ctx.instruction_type)
    if (!insValues.has(cur)) {
      return false
    }
  }
  const catValues = _selectorValues(selector.category || selector.categories)
  if (catValues && !catValues.has("*")) {
    const cur = _safeUpper(ctx.instruction_category)
    if (!catValues.has(cur)) {
      return false
    }
  }
  return true
}

function _actualSnapshot(ctx: Record<string, unknown>, pred: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const name of [..._extractVars(pred)].sort()) {
    if (name in ctx) {
      const val = ctx[name]
      if (val instanceof Set) {
        out[name] = [...val].sort()
      } else {
        out[name] = val
      }
    }
  }
  for (const key of ["tool_name", "instruction_type", "instruction_category", "scope"]) {
    if (!(key in out) && key in ctx) {
      out[key] = ctx[key]
    }
  }
  return out
}

function _buildRuleDecision(rule: Record<string, unknown>, index: number, ctx: Record<string, unknown>): RuleDecision {
  const ruleId = _safeStr(rule.id, `UG-${String(index).padStart(3, "0")}`)
  const title = _safeStr(rule.title, ruleId)
  const description = _safeStr(rule.description, title)
  const effect = _safeUpper(rule.effect, "BLOCK") || "BLOCK"
  let message = _safeStr(rule.message)
  if (!message) {
    message = description || title || ruleId
  }
  return {
    index,
    rule_id: ruleId,
    title,
    description,
    effect: effect as "BLOCK" | "ALLOW" | "REQUIRE_APPROVAL",
    scope: _safeLower(rule.scope, "tool"),
    message,
    predicate: rule.predicate,
    selector: _safeDict(rule.selector),
    actual: _actualSnapshot(ctx, rule.predicate),
    source: _safeStr(rule.source),
  }
}

function _evaluateRules(
  rules: Record<string, unknown>[],
  ctx: Record<string, unknown>,
  cfg: Record<string, unknown>,
): RuleDecision | null {
  for (let idx = 0; idx < rules.length; idx++) {
    const rule = rules[idx]
    if (typeof rule !== "object" || rule === null || Array.isArray(rule)) continue
    if (!rule.enabled && rule.enabled !== undefined && rule.enabled !== null) continue
    if (!_selectorMatches(rule, ctx, cfg)) continue
    const pred = rule.predicate
    if (_evalPredicate(pred, ctx)) {
      return _buildRuleDecision(rule, idx + 1, ctx)
    }
  }
  return null
}

function _rulesWithoutRuleIds(rules: Record<string, unknown>[], dropIds: Set<string>): Record<string, unknown>[] {
  return rules.filter((r) => {
    if (typeof r !== "object" || r === null) return false
    return _safeStr(r.id, "") !== "" && !dropIds.has(_safeStr(r.id, ""))
  })
}

function _buildToolContext(
  toolName: string,
  toolCallId: string,
  argsDict: Record<string, unknown>,
  ins: Record<string, unknown> | undefined,
  cfg: Record<string, unknown>,
): Record<string, unknown> {
  let md: Record<string, unknown>
  if (ins && typeof ins === "object") {
    md = _extractMetadataView(ins)
  } else {
    md = {
      instruction_type: "EXEC",
      instruction_category: "EXECUTION.Env",
      trustworthiness: "UNKNOWN",
      confidentiality: "UNKNOWN",
      prop_trustworthiness: "UNKNOWN",
      prop_confidentiality: "UNKNOWN",
      confidence: "UNKNOWN",
      authority: "UNKNOWN",
      reversible: false,
      risk: "UNKNOWN",
      custom: {},
      tags: new Set(),
      review_required: false,
      approval_required: false,
      destructive: false,
    }
  }

  const instructionType = md.instruction_type || "EXEC"
  const category = md.instruction_category || "EXECUTION.Env"

  const custom = md.custom && typeof md.custom === "object" && !Array.isArray(md.custom)
    ? md.custom as Record<string, unknown>
    : {}
  const execParse = custom.exec_parse && typeof custom.exec_parse === "object" && !Array.isArray(custom.exec_parse)
    ? custom.exec_parse as Record<string, unknown>
    : {}

  const action = _safeUpper(argsDict.action, "")

  const pathHint = _safeStr(
    argsDict.path || argsDict.file_path || argsDict.target_path ||
    argsDict.destination_path || argsDict.output_path || argsDict.dest_path || argsDict.dst || "",
  )
  const pathHintUpper = pathHint ? pathHint.toUpperCase() : ""
  const pathBasename = pathHint ? path.basename(pathHint).toUpperCase() : ""
  const pathDirname = pathHint ? path.dirname(pathHint).toUpperCase() : ""

  const directTargetBasenames = pathBasename ? [pathBasename].sort() : []

  const readPaths = [...new Set(
    [argsDict.path, argsDict.file_path, argsDict.directory, argsDict.dir, argsDict.source, argsDict.url]
      .filter((x: unknown): x is string => !!(typeof x === "string" && x.trim()))
      .map((x: string) => x.trim())
  )].sort()

  const execPathTokens = [...new Set(
    (Array.isArray(execParse.path_tokens) ? execParse.path_tokens : [])
      .filter((x: unknown): x is string => !!(typeof x === "string" && x.trim()))
      .map((x: string) => x.toUpperCase())
  )].sort()

  const execWriteTargets = [...new Set(
    (Array.isArray(execParse.write_targets) ? execParse.write_targets : [])
      .filter((x: unknown): x is string => !!(typeof x === "string" && x.trim()))
      .map((x: string) => x.toUpperCase())
  )].sort()

  const execWriteTargetBasenames = [...new Set(
    (Array.isArray(execParse.write_targets) ? execParse.write_targets : [])
      .filter((x: unknown): x is string => !!(typeof x === "string" && x.trim()))
      .map((x: string) => path.basename(x).toUpperCase())
  )].sort()

  const argTextUpper = _safeUpper(
    JSON.stringify(argsDict),
    "",
  )
  const hasExternalUrl = argTextUpper.includes("HTTP://") || argTextUpper.includes("HTTPS://")

  const canonicalToolName = _canonicalToolForUnaryGate(toolName, cfg)

  return {
    scope: "tool",
    tool_name: toolName,
    canonical_tool_name: canonicalToolName,
    tool_call_id: toolCallId,
    instruction_type: instructionType,
    instruction_category: category,
    missing_instruction: !ins,
    arg_total_str_len: _estimateArgumentStringBudget(argsDict),
    raw_args: argsDict,
    ...md,
    action,
    path_hint: pathHintUpper,
    path_basename: pathBasename,
    path_dirname: pathDirname,
    direct_target_basenames: directTargetBasenames,
    read_paths: readPaths,
    exec_path_tokens: execPathTokens,
    exec_write_targets: execWriteTargets,
    exec_write_target_basenames: execWriteTargetBasenames,
    arg_text_upper: argTextUpper,
    has_external_url: hasExternalUrl,
    custom_io_kind: _safeUpper(custom.io_kind, ""),
    custom_flow_role: _safeUpper(custom.flow_role, ""),
    custom_taint_role: _safeUpper(custom.taint_role, ""),
  }
}

function _buildRespondContext(ins: Record<string, unknown>): Record<string, unknown> {
  const md = _extractMetadataView(ins)
  md.instruction_type = "RESPOND"
  md.instruction_category = md.instruction_category || "EXECUTION.Human"
  return {
    scope: "respond",
    tool_name: "@instruction",
    tool_call_id: "",
    instruction_type: "RESPOND",
    instruction_category: md.instruction_category,
    missing_instruction: false,
    arg_total_str_len: 0,
    ...md,
  }
}

function _formatActual(actual: Record<string, unknown>): string {
  const keyMap: Record<string, string> = {
    confidence: "置信级别",
    trustworthiness: "可信级别",
    confidentiality: "保密级别",
    prop_confidentiality: "传播保密级别",
    prop_trustworthiness: "传播可信级别",
    tool_name: "工具",
    canonical_tool_name: "规范工具名",
    instruction_type: "指令类型",
    instruction_category: "指令类别",
    scope: "范围",
    risk: "风险级别",
    tags: "标签",
    arg_total_str_len: "参数总长度",
    approval_required: "需要审批",
    review_required: "需要复核",
    destructive: "破坏性标记",
    reversible: "可回退",
    direct_target_basenames: "直接目标文件",
    exec_write_target_basenames: "潜在写入目标文件",
    action: "动作",
    has_external_url: "包含外部链接",
    missing_instruction: "缺少元数据",
  }
  const scopeMap: Record<string, string> = { tool: "工具调用", respond: "直接回复" }
  const boolMap = new Map<boolean, string>([[true, "是"], [false, "否"]])

  const parts: string[] = []
  for (const [k, v] of Object.entries(actual)) {
    let label = keyMap[k] || k
    let displayVal = v
    if (k === "scope" && typeof v === "string") {
      displayVal = scopeMap[v] || v
    } else if (typeof v === "boolean") {
      displayVal = boolMap.get(v) || String(v)
    } else if (Array.isArray(v)) {
      displayVal = v.join(", ")
    }
    parts.push(`${label}=${displayVal}`)
  }
  return parts.join("，")
}

function _friendlyRuleLabel(decision: RuleDecision): string {
  return `\`${decision.rule_id}\`（第 ${decision.index} 条）`
}

function _localizedRuleMeaning(decision: RuleDecision): string {
  const ruleId = _safeUpper(decision.rule_id)
  const mapping: Record<string, string> = {
    "UG-001": "系统暂时无法确认这一步的具体操作内容。",
    "UG-010": "这次请求包含的内容过多，系统暂时无法可靠核验。",
    "UG-020": "当前执行请求的识别还不充分。",
    "UG-021": "当前执行请求的来源还不够可信。",
    "UG-030": "这一步属于高风险执行。",
    "UG-031": "这一步需要先审批。",
    "UG-032": "这一步会造成直接改动，但当前缺少可靠的回退条件。",
    "UG-040": "这一步命中了敏感或高风险标记。",
    "UG-050": "当前回复内容不适合直接展示。",
    "UG-060": "这一步会直接修改受保护文件。",
    "UG-061": "这一步会通过命令修改受保护文件。",
    "UG-062": "这一步会把受保护文件的修改指令发给其他对象。",
    "UG-063": "这一步会读取系统敏感文件。",
    "UG-070": "这一步会修改网关或代理的外部转发配置。",
  }
  return mapping[ruleId] || "当前操作存在系统不能直接放行的安全风险。"
}

function _toolBlockReason(decision: RuleDecision, ctx: Record<string, unknown>): string {
  const ruleId = _safeUpper(decision.rule_id)
  const directTargets = (ctx.direct_target_basenames || []) as string[]
  const execTargets = (ctx.exec_write_target_basenames || []) as string[]
  const directTarget = directTargets[0] || ""
  const execTarget = execTargets[0] || ""

  if (ruleId === "UG-001") return "系统暂时无法确认这一步具体会执行什么，已暂停执行。"
  if (ruleId === "UG-010") return "这次请求包含的内容过多，系统暂时无法逐项确认其安全性，已暂停执行。"
  if (ruleId === "UG-020") return "这一步会触发执行操作，但当前对其用途和影响的识别还不充分，已暂停执行。"
  if (ruleId === "UG-021") return "这一步会触发执行操作，但驱动它的来源不够可靠，已暂停执行。"
  if (ruleId === "UG-030") return "这一步属于高风险执行，可能直接影响当前环境或数据，已暂停执行。"
  if (ruleId === "UG-031") return "这一步需要先经过审批，当前不会直接执行。"
  if (ruleId === "UG-032") {
    if (directTarget) return `这一步会直接改动 \`${directTarget}\`，但当前没有可靠的撤回方式，已暂停执行。`
    if (execTarget) return `这一步会通过命令改动 \`${execTarget}\`，但当前没有可靠的撤回方式，已暂停执行。`
    return "这一步会直接改动现有内容，但当前没有可靠的撤回方式，已暂停执行。"
  }
  if (ruleId === "UG-040") return "这一步命中了敏感或高风险标记，当前不会直接继续。"
  if (ruleId === "UG-050") return "当前回复包含不适合直接展示的内容，系统已暂停输出。"
  if (ruleId === "UG-060") {
    const src = _safeStr(decision.source, "")
    if (src === "protected_identity_llm") {
      const base = directTarget
        ? `这一步会直接修改受保护文件 \`${directTarget}\`，已暂停执行。`
        : "这一步会直接修改受保护的系统身份或控制文件，已暂停执行。"
      const extra = _safeStr(decision.message)
      if (extra) return `${base}\n\n（审核说明：${extra}）`
      return base
    }
    if (directTarget) return `这一步会直接修改受保护文件 \`${directTarget}\`，已暂停执行。`
    return "这一步会直接修改受保护的系统身份或控制文件，已暂停执行。"
  }
  if (ruleId === "UG-061") {
    const src = _safeStr(decision.source, "")
    if (src === "protected_identity_llm") {
      const base = execTarget
        ? `这一步会通过命令修改受保护文件 \`${execTarget}\`，已暂停执行。`
        : "这一步会通过命令修改受保护的系统身份或控制文件，已暂停执行。"
      const extra = _safeStr(decision.message)
      if (extra) return `${base}\n\n（审核说明：${extra}）`
      return base
    }
    if (execTarget) return `这一步会通过命令修改受保护文件 \`${execTarget}\`，已暂停执行。`
    return "这一步会通过命令修改受保护的系统身份或控制文件，已暂停执行。"
  }
  if (ruleId === "UG-062") return "这一步会把修改受保护文件的指令发送给其他对象，已暂停执行。"
  if (ruleId === "UG-063") return "这一步会读取系统敏感文件，已暂停执行。"
  if (ruleId === "UG-070") return "这一步会修改网关或代理配置，并把后续请求转向外部地址，已暂停执行。"
  return "当前操作触发了系统安全保护，已暂停执行。"
}

function _renderToolInstructionBlock(ctx: Record<string, unknown>): string {
  const toolName = _safeStr(ctx.tool_name, "@tool")
  const rawArgs = ctx.raw_args && typeof ctx.raw_args === "object" && !Array.isArray(ctx.raw_args)
    ? ctx.raw_args as Record<string, unknown>
    : {}

  if (toolName === "exec" || toolName === "process") {
    const command = _safeStr(rawArgs.command || rawArgs.cmd || rawArgs.script)
    if (command) return `\`\`\`bash\n${command}\n\`\`\``
  }

  return "```json\n" + JSON.stringify(rawArgs, null, 2) + "\n```"
}

function _unaryPolicyTitle(decision: RuleDecision): string {
  const ruleId = _safeUpper(decision.rule_id)
  const mapping: Record<string, string> = {
    "UG-001": "信息不足，无法安全判断",
    "UG-010": "请求内容过多，无法可靠确认",
    "UG-020": "执行意图识别不够可靠",
    "UG-021": "执行依据不够可信",
    "UG-030": "高风险执行动作",
    "UG-031": "需要审批的动作",
    "UG-032": "不可安全回退的动作",
    "UG-040": "命中敏感或高风险标记",
    "UG-050": "当前回复不适合直接展示",
    "UG-060": "直接修改受保护文件",
    "UG-061": "间接修改受保护文件",
    "UG-062": "传播受保护文件修改指令",
    "UG-063": "读取系统敏感文件",
    "UG-070": "外部重定向或代理变更",
  }
  return mapping[ruleId] || "安全保护已触发"
}

function _unaryRuleReference(decision: RuleDecision): string {
  const parts: string[] = [`- 规则编号：${decision.rule_id}`]
  parts.push(`- 规则含义：${_localizedRuleMeaning(decision)}`)
  parts.push(`- 详情见：${RULE_DETAILS_URL}`)
  return parts.join("\n")
}

function _friendlyToolBlock(decision: RuleDecision, ctx: Record<string, unknown>): string {
  return [
    "## ⚠️ 安全策略拦截确认",
    "",
    "### 1. 触发指令",
    _renderToolInstructionBlock(ctx),
    "",
    "### 2. 拦截说明",
    `[${_unaryPolicyTitle(decision)}]：${_toolBlockReason(decision, ctx)}`,
    "",
    "### 3. 规则说明",
    _unaryRuleReference(decision),
  ].join("\n")
}

function _friendlyRespondBlock(decision: RuleDecision, ctx: Record<string, unknown>): string {
  return [
    "## ⚠️ 安全策略拦截确认",
    "",
    "### 1. 触发指令",
    "```text\nRESPOND\n```",
    "",
    "### 2. 拦截说明",
    `[${_unaryPolicyTitle(decision)}]：${_toolBlockReason(decision, ctx)}`,
    "",
    "### 3. 规则说明",
    _unaryRuleReference(decision),
  ].join("\n")
}

function _appendUniqueError(errors: string[], seen: Set<string>, message: string): void {
  if (!seen.has(message)) {
    errors.push(message)
    seen.add(message)
  }
}

function extractToolCalls(response: Record<string, unknown>): Record<string, unknown>[] {
  const tcs = response.tool_calls
  if (Array.isArray(tcs)) {
    return tcs.filter((tc): tc is Record<string, unknown> => tc !== null && typeof tc === "object" && !Array.isArray(tc))
  }
  return []
}

function parseToolCall(tc: Record<string, unknown>): {
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

function writeBackToolArgs(tc: Record<string, unknown>, args: Record<string, unknown>, wasJsonStr: boolean): Record<string, unknown> {
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

export class UnaryGatePolicy extends Policy {
  private cfg: Record<string, unknown>
  private ruleBundle: Record<string, unknown> | null = null

  constructor(cfg: Record<string, unknown> = {}) {
    super()
    this.cfg = cfg
  }

  private _getRuleBundle(): Record<string, unknown> {
    if (!this.ruleBundle) {
      const unaryCfg = _safeDict(this.cfg.unary_gate)
      const ruleFile = _safeStr(unaryCfg.rule_file)
      if (ruleFile) {
        try {
          const { readFileSync } = require("node:fs")
          const text = readFileSync(ruleFile, "utf-8")
          const data = JSON.parse(text)
          if (data && typeof data === "object" && !Array.isArray(data)) {
            this.ruleBundle = data as Record<string, unknown>
          }
        } catch {
          this.ruleBundle = this._legacyRuleBundle()
        }
      } else {
        this.ruleBundle = this._legacyRuleBundle()
      }
    }
    return this.ruleBundle ?? {}
  }

  private _legacyRuleBundle(): Record<string, unknown> {
    const rules: Record<string, unknown>[] = []
    const unaryCfg = _safeDict(this.cfg.unary_gate)
    const policyCfg = _safeDict(this.cfg.policy)
    const denyCfg = _safeDict(policyCfg.deny)

    const denyTools = _normList(denyCfg.tools)
    if (denyTools.length > 0) {
      rules.push({
        id: "UG-005",
        title: "tool blacklist",
        description: "block tools in the deny list",
        scope: "tool",
        selector: { tool: denyTools.map((t) => t.toUpperCase()) },
        predicate: { const: true },
        effect: "BLOCK",
        message: "工具调用被黑名单阻止。",
        enabled: true,
        source: "config",
      })
    }

    // UG-006: instruction type filter
    const denyInstructionTypes = _normList(denyCfg.instruction_types)
    if (denyInstructionTypes.length > 0) {
      rules.push({
        id: "UG-006",
        title: "instruction type blacklist",
        description: "block instruction types in the deny list",
        scope: "any",
        selector: { instruction_type: denyInstructionTypes.map((t) => t.toUpperCase()) },
        predicate: { const: true },
        effect: "BLOCK",
        message: "指令类型被黑名单阻止。",
        enabled: true,
        source: "config",
      })
    }

    const allowCfg = _safeDict(policyCfg.allow)
    const allowInstructionTypes = _normList(allowCfg.instruction_types)
    if (allowInstructionTypes.length > 0) {
      rules.push({
        id: "UG-006",
        title: "instruction type whitelist",
        description: "block instruction types not in the allow list",
        scope: "any",
        selector: {},
        predicate: { not_in: [{ var: "instruction_type" }, { const: allowInstructionTypes.map((t) => t.toUpperCase()) }] },
        effect: "BLOCK",
        message: "指令类型不在白名单中。",
        enabled: true,
        source: "config",
      })
    }

    if (unaryCfg.fail_closed_on_missing_instruction) {
      rules.push({
        id: "UG-001",
        title: "missing instruction metadata",
        description: "block tool call when kernel did not attach instruction metadata",
        scope: "tool",
        selector: {},
        predicate: { truthy: { var: "missing_instruction" } },
        effect: "BLOCK",
        message: "当前 tool_call 没有找到对应的 instruction metadata，策略无法安全判定。",
        enabled: true,
        source: "legacy",
      })
    }

    const inputBudget = _safeDict(this.cfg.input_budget)
    const maxStrLen = Number(inputBudget.max_str_len) || 0
    if (maxStrLen > 0) {
      rules.push({
        id: "UG-010",
        title: "argument string budget",
        description: `block when total argument string length exceeds ${maxStrLen}`,
        scope: "tool",
        selector: {},
        predicate: { gt: [{ var: "arg_total_str_len" }, { const: maxStrLen }] },
        effect: "BLOCK",
        message: `total argument string length > max_str_len ${maxStrLen}`,
        enabled: true,
        source: "legacy",
      })
    }

    const sec = _safeDict(unaryCfg.security)
    if (sec.min_confidence) {
      rules.push({
        id: "UG-020",
        title: "execution confidence too low",
        description: "block when confidence < required",
        scope: "any",
        selector: {},
        predicate: { lt: [{ var: "confidence" }, { const: sec.min_confidence }] },
        effect: "BLOCK",
        message: "confidence < required",
        enabled: true,
        source: "legacy",
      })
    }
    if (sec.min_trustworthiness) {
      rules.push({
        id: "UG-021",
        title: "execution trustworthiness too low",
        description: "block when trustworthiness < required",
        scope: "any",
        selector: {},
        predicate: { lt: [{ var: "trustworthiness" }, { const: sec.min_trustworthiness }] },
        effect: "BLOCK",
        message: "trustworthiness < required",
        enabled: true,
        source: "legacy",
      })
    }

    const risk = _safeDict(unaryCfg.risk)
    const blockedRisks = risk.blocked_risks
    if (blockedRisks) {
      const riskList = [..._normSet(blockedRisks)].sort()
      rules.push({
        id: "UG-030",
        title: "high risk execution",
        description: `block when risk in ${riskList.join(", ")}`,
        scope: "any",
        selector: {},
        predicate: { in: [{ var: "risk" }, { const: riskList }] },
        effect: "BLOCK",
        message: "这一步属于高风险执行，可能直接影响当前环境或数据，已暂停执行。",
        enabled: true,
        source: "legacy",
      })
    }
    if (risk.block_approval_required) {
      rules.push({
        id: "UG-031",
        title: "approval required",
        description: "block when approval_required=true",
        scope: "any",
        selector: {},
        predicate: { truthy: { var: "approval_required" } },
        effect: "BLOCK",
        message: "这一步需要先经过审批，当前不会直接执行。",
        enabled: true,
        source: "legacy",
      })
    }
    if (risk.block_destructive) {
      rules.push({
        id: "UG-032",
        title: "destructive and not reversible",
        description: "block when destructive=true and reversible=false",
        scope: "any",
        selector: {},
        predicate: { all: [{ truthy: { var: "destructive" } }, { falsy: { var: "reversible" } }] },
        effect: "BLOCK",
        message: "这一步会直接改动现有内容，但当前没有可靠的撤回方式，已暂停执行。",
        enabled: true,
        source: "legacy",
      })
    }

    const tags = _safeDict(unaryCfg.tags)
    const blockedTags = tags.blocked_tags
    if (blockedTags) {
      const tagList = [..._normSet(blockedTags)].sort()
      rules.push({
        id: "UG-040",
        title: "blocked tags",
        description: `block when tags intersect with ${tagList.join(", ")}`,
        scope: "any",
        selector: {},
        predicate: { intersects: [{ var: "tags" }, { const: tagList }] },
        effect: "BLOCK",
        message: "这一步命中了敏感或高风险标记，当前不会直接继续。",
        enabled: true,
        source: "legacy",
      })
    }

    rules.push({
      id: "UG-050",
      title: "respond confidentiality too high",
      description: "block when prop_confidentiality > MID",
      scope: "respond",
      selector: { instruction_type: ["RESPOND"] },
      predicate: { gt: [{ var: "prop_confidentiality" }, { const: "MID" }] },
      effect: "BLOCK",
      message: "当前回复内容不适合直接展示。",
      enabled: true,
      source: "legacy",
    })

    rules.push({
      id: "UG-060",
      title: "protected identity or control file direct mutation",
      description: "block direct write/edit to protected identity/control file",
      scope: "tool",
      selector: { tool: ["write", "edit"] },
      predicate: { intersects: [{ var: "direct_target_basenames" }, { const: [...UG060_PROTECTED_BASENAMES] }] },
      effect: "BLOCK",
      message: "这一步会直接修改受保护文件，已暂停执行。",
      enabled: true,
      source: "legacy",
    })

    rules.push({
      id: "UG-061",
      title: "protected identity or control file exec write target",
      description: "block exec/process that writes to protected identity/control file",
      scope: "tool",
      selector: { tool: ["exec", "process"] },
      predicate: { intersects: [{ var: "exec_write_target_basenames" }, { const: [...UG060_PROTECTED_BASENAMES] }] },
      effect: "BLOCK",
      message: "这一步会通过命令修改受保护文件，已暂停执行。",
      enabled: true,
      source: "legacy",
    })

    rules.push({
      id: "UG-062",
      title: "protected identity file modification instruction propagation",
      description: "block delegation of protected file modification",
      scope: "tool",
      selector: { instruction_type: ["DELEGATE"] },
      predicate: { intersects: [{ var: "tags" }, { const: ["MODIFY_PROTECTED_FILE"] }] },
      effect: "BLOCK",
      message: "这一步会把修改受保护文件的指令发送给其他对象，已暂停执行。",
      enabled: true,
      source: "legacy",
    })

    rules.push({
      id: "UG-070",
      title: "gateway external redirect",
      description: "block gateway config change with external URL",
      scope: "tool",
      selector: { tool: ["gateway"] },
      predicate: { all: [{ truthy: { var: "has_external_url" } }, { in: [{ var: "action" }, { const: ["config.apply", "config.patch"] }] }] },
      effect: "BLOCK",
      message: "这一步会修改网关或代理配置，并把后续请求转向外部地址，已暂停执行。",
      enabled: true,
      source: "legacy",
    })

    rules.push({
      id: "UG-063",
      title: "protected system sensitive file read",
      description: "block read of system sensitive files like /etc/shadow",
      scope: "tool",
      selector: { tool: ["read", "read_file"] },
      predicate: { intersects: [{ var: "read_paths" }, { const: [...UG063_PROTECTED_READ_PATHS] }] },
      effect: "BLOCK",
      message: "这一步会读取系统敏感文件，已暂停执行。",
      enabled: true,
      source: "legacy",
    })

    return {
      evaluation_mode: "first_match",
      rules,
      source: "legacy-config-compiled",
    }
  }

  async check(
    instructions: Record<string, unknown>[],
    currentResponse: Record<string, unknown>,
    latestInstructions: Record<string, unknown>[],
    traceId: string,
  ): Promise<PolicyCheckResult> {
    const response = { ...currentResponse }
    const toolCalls = extractToolCalls(response)
    const latestIdx = _latestToolInstrIndex(latestInstructions)
    const ruleBundle = this._getRuleBundle()
    const rules = Array.isArray(ruleBundle.rules) ? ruleBundle.rules as Record<string, unknown>[] : []

    const pilCfg = _safeDict(ruleBundle.protected_identity_llm)
    const llmEnabled = !!pilCfg.enabled
    const rulesForEval = llmEnabled
      ? _rulesWithoutRuleIds(rules, new Set(["UG-060", "UG-061"]))
      : [...rules]

    const errors: string[] = []
    const seenErrors = new Set<string>()
    const kept: Record<string, unknown>[] = []
    let changed = false

    for (const tc of toolCalls) {
      const { toolName, toolCallId, argsDict, wasJsonStr } = parseToolCall(tc)
      const ins = latestIdx.get(toolCallId || "")
      const ctx = _buildToolContext(toolName, toolCallId || "", argsDict, ins, this.cfg)

      const decision = _evaluateRules(rulesForEval, ctx, this.cfg)

      const newTc = writeBackToolArgs(tc, argsDict, wasJsonStr)
      if (JSON.stringify(newTc) !== JSON.stringify(tc)) {
        changed = true
      }

      if (decision === null) {
        kept.push(newTc)
        continue
      }

      const userMsg = _friendlyToolBlock(decision, ctx)
      _appendUniqueError(errors, seenErrors, userMsg)
    }

    if (errors.length > 0) {
      response.tool_calls = kept.length > 0 ? kept : null
      if (kept.length === 0) {
        response.function_call = null
        if (typeof response.content !== "string" || !response.content) {
          response.content = errors.slice(0, 3).join("\n\n")
        }
      }
      return {
        modified: true,
        response,
        error_type: errors.join("\n\n"),
        inactivate_error_type: null,
        policy_names: [],
        policy_sources: {},
      }
    }

    const content = response.content
    if (typeof content === "string" && content.trim()) {
      const respondIns = _findLatestRespondInstruction(latestInstructions)
      if (respondIns) {
        const ctx = _buildRespondContext(respondIns)
        const decision = _evaluateRules(rulesForEval, ctx, this.cfg)
        if (decision !== null) {
          const userMsg = _friendlyRespondBlock(decision, ctx)
          response.content = userMsg
          return {
            modified: true,
            response,
            error_type: userMsg,
            inactivate_error_type: null,
            policy_names: [],
            policy_sources: {},
          }
        }
      }
    }

    if (changed) {
      response.tool_calls = kept
      return {
        modified: true,
        response,
        error_type: null,
        inactivate_error_type: null,
        policy_names: [],
        policy_sources: {},
      }
    }

    return {
      modified: false,
      response: currentResponse,
      error_type: null,
      inactivate_error_type: null,
      policy_names: [],
      policy_sources: {},
    }
  }
}
