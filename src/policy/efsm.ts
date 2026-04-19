import crypto from "node:crypto"
import type { PolicyCheckResult } from "../types/policy.ts"
import { Policy } from "./policy.ts"

interface EfsmStepResult {
  allow: boolean
  effect: string
  reason: string
  next_state: string
  matched_transition: string | null
  meta: Record<string, unknown> | null
}

interface PlanState {
  plan_ts: number | null
  plan_text: string
  planned_paths: Set<string>
  planned_tools: Set<string>
}

function _safeStr(v: unknown, defaultVal: string = ""): string {
  return typeof v === "string" && v.trim() ? v.trim() : defaultVal
}

function _safeUpper(v: unknown, defaultVal: string = ""): string {
  const s = _safeStr(v, defaultVal)
  return s ? s.toUpperCase() : defaultVal
}

function _safeDict(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v)
    ? v as Record<string, unknown>
    : {}
}

function _sha256(s: string): string {
  return crypto.createHash("sha256").update(s, "utf-8").digest("hex")
}

function _safeJsonDumps(obj: unknown): string {
  return JSON.stringify(obj, null, 0)
}

function _computeOpId(traceId: string, tool: string, args: Record<string, unknown>): string {
  const toolNorm = (tool || "").trim() || "unknown_tool"
  const canonJson = _safeJsonDumps(args)
  return _sha256(`${traceId}|${toolNorm}|${canonJson}`).slice(0, 24)
}

function _splitHistoryAndLatest(
  instructions: Record<string, unknown>[],
  latestInstructions: Record<string, unknown>[],
): [Record<string, unknown>[], Record<string, unknown>[]] {
  if (!instructions.length || !latestInstructions.length) {
    return [instructions, latestInstructions]
  }

  const n = latestInstructions.length
  const tail = instructions.slice(-n)
  const tailIds = tail.map((t) => t.id)
  const latestIds = latestInstructions.map((t) => t.id)
  if (tailIds.every((x) => typeof x === "string") && JSON.stringify(tailIds) === JSON.stringify(latestIds)) {
    return [instructions.slice(0, -n), latestInstructions]
  }

  const tailSteps = tail.map((t) => t.runtime_step)
  const latestSteps = latestInstructions.map((t) => t.runtime_step)
  if (tailSteps.every((x) => typeof x === "number") && JSON.stringify(tailSteps) === JSON.stringify(latestSteps)) {
    return [instructions.slice(0, -n), latestInstructions]
  }

  return [instructions, latestInstructions]
}

function _friendlyApprovalMessage(
  toolName: string,
  instructionType: string,
  currentState: unknown,
  msg: string,
): string {
  const text = (msg || "").trim()
  const stateText = currentState !== null && currentState !== undefined ? String(currentState) : "UNKNOWN"
  const lines: string[] = [
    `我暂时没有执行工具 \`${toolName}\`。`,
    `当前流程阶段：\`${stateText}\`。`,
    `你请求的动作类型：\`${instructionType}\`。`,
    "原因：按照当前流程规则，这一步在执行前需要先获得用户确认。",
    "这通常表示该操作可能带来实际副作用，或者必须在确认后才能继续。",
  ]
  if (text) lines.push(`补充说明：${text}`)
  lines.push("如果你确认要继续，请先完成确认步骤，然后再重新发起这一步操作。")
  return lines.join("\n")
}

function _friendlyEfsmBlockMessage(
  toolName: string,
  instructionType: string,
  currentState: unknown,
  reason: string | null,
): string {
  const text = (reason || "").trim()
  const stateText = currentState !== null && currentState !== undefined ? String(currentState) : "UNKNOWN"
  const lines: string[] = [
    `我没有执行工具 \`${toolName}\`。`,
    `当前流程阶段：\`${stateText}\`。`,
    `你请求的动作类型：\`${instructionType}\`。`,
    "原因：当前流程在这个阶段不允许执行这类操作。",
  ]
  if (text) lines.push(`补充说明：${text}`)
  lines.push("通常需要先完成前一步、进入允许该操作的阶段，或改用当前阶段允许的操作后再试。")
  return lines.join("\n")
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

function _toolToInstructionType(toolName: string, cfg: Record<string, unknown>): string {
  const t = (toolName || "").trim().toLowerCase()
  const mapping = _safeDict(cfg.tool_to_instruction_type)
  const v = mapping[t]
  if (typeof v === "string" && v.trim()) return v.trim().toUpperCase()
  if (new Set(["write", "fs_write", "file_write"]).has(t)) return "WRITE"
  if (new Set(["read", "fs_read", "file_read"]).has(t)) return "READ"
  if (new Set(["exec", "shell", "run", "cmd"]).has(t)) return "EXEC"
  return "EXEC"
}

function _instructionTypeToCategory(instructionType: string): string | null {
  const it = (instructionType || "").trim().toUpperCase()
  if (!it) return null
  if (new Set(["REASON", "PLAN", "CRITIQUE"]).has(it)) return "COGNITIVE.Reasoning"
  if (new Set(["RESPOND", "ASK", "USER_MESSAGE"]).has(it)) return "EXECUTION.Human"
  if (new Set(["READ", "WRITE", "EXEC", "WAIT"]).has(it)) return "EXECUTION.Env"
  if (it === "HANDOFF") return "EXECUTION.Agent"
  return null
}

function _collectPathsFromArgs(args: Record<string, unknown>): string[] {
  const paths: string[] = []
  if (!args || typeof args !== "object") return paths
  const pathKeys = new Set(["path", "file_path", "file", "filename", "src", "dst", "directory", "dir"])
  for (const [k, v] of Object.entries(args)) {
    if (typeof v === "string" && v.trim() && pathKeys.has(k.toLowerCase())) {
      paths.push(v.trim().replace(/\\/g, "/"))
    }
  }
  return paths
}

function _efsmGuard(
  name: string,
  plan: PlanState,
  payload: Record<string, unknown>,
): boolean {
  const n = (name || "").trim()
  if (!n) return true
  if (n === "always") return true
  if (n === "path_in_recent_plan") {
    const args = payload.args
    if (!args || typeof args !== "object" || Array.isArray(args)) return false
    const paths = _collectPathsFromArgs(args as Record<string, unknown>)
    if (!paths.length) return false
    return paths.some((p) => plan.planned_paths.has(p))
  }
  if (n === "tool_in_recent_plan") {
    const tool = payload.tool
    if (typeof tool !== "string" || !tool.trim()) return false
    return plan.planned_tools.has(tool.trim())
  }
  if (n === "has_recent_plan") {
    return !!plan.plan_text
  }
  return false
}

function _efsmApplyActions(
  actions: unknown,
  vars_: Record<string, unknown>,
  plan: PlanState,
  payload: Record<string, unknown>,
): void {
  let actionList: string[]
  if (typeof actions === "string") {
    actionList = [actions]
  } else if (Array.isArray(actions)) {
    actionList = actions.filter((a): a is string => !!(typeof a === "string" && a.trim()))
  } else {
    return
  }
  for (const a of actionList) {
    if (a === "cache_plan") {
      vars_.plan_text = plan.plan_text
      vars_.planned_paths = [...plan.planned_paths]
      vars_.planned_tools = [...plan.planned_tools]
      vars_.plan_ts = plan.plan_ts
    } else if (a === "set_pending") {
      vars_.pending = {
        event: payload.event,
        tool: payload.tool,
      }
    } else if (a === "clear_pending") {
      delete vars_.pending
    }
  }
}

function _buildPlanState(instructions: Record<string, unknown>[], cfg: Record<string, unknown>): PlanState {
  const efsmCfg = _safeDict(cfg.efsm)
  const ttl = Number(efsmCfg.plan_ttl_seconds) || 600

  let planText = ""
  let planTs: number | null = null
  const plannedPaths = new Set<string>()
  const plannedTools = new Set<string>()

  for (let i = instructions.length - 1; i >= 0; i--) {
    const ins = instructions[i]
    const it = _safeUpper(ins.instruction_type)
    if (it !== "PLAN") continue
    const content = ins.content
    if (typeof content === "string") {
      planText = content
    } else {
      planText = _safeJsonDumps(content)
    }
    const ts = ins.ts
    if (typeof ts === "number") planTs = ts

    const pathRegex = /(?:~|\/)[\w.\-~/]+/g
    let m: RegExpExecArray | null
    while ((m = pathRegex.exec(planText)) !== null) {
      plannedPaths.add(m[0])
    }
    break
  }

  if (planTs !== null && ttl > 0) {
    const now = Date.now() / 1000
    if ((now - planTs) > ttl) {
      planText = ""
      planTs = null
      plannedPaths.clear()
      plannedTools.clear()
    }
  }

  return { plan_ts: planTs, plan_text: planText.slice(0, 4000), planned_paths: plannedPaths, planned_tools: plannedTools }
}

function _efsmStep(
  cfg: Record<string, unknown>,
  currentState: string,
  vars_: Record<string, unknown>,
  plan: PlanState,
  event: string,
  payload: Record<string, unknown>,
): EfsmStepResult {
  const efsmCfg = _safeDict(cfg.efsm)
  if (!efsmCfg.enabled) {
    return { allow: true, effect: "ALLOW", reason: "efsm disabled", next_state: currentState, matched_transition: null, meta: null }
  }

  const transitions = (() => {
    const trs = efsmCfg.transitions
    if (Array.isArray(trs) && trs.length > 0) {
      const cleaned = trs.filter((t): t is Record<string, unknown> => t !== null && typeof t === "object" && !Array.isArray(t))
      cleaned.sort((a, b) => (Number(b.priority) || 0) - (Number(a.priority) || 0))
      return cleaned
    }
    return [
      { id: "idle_plan", from: "IDLE", event: "PLAN", to: "PLANNED", actions: ["cache_plan"], effect: "ALLOW", priority: 100 },
      { id: "planned_exec_ok_path", from: "PLANNED", event: "EXEC", to: "EXECUTING", guard: "path_in_recent_plan", effect: "ALLOW", priority: 70 },
      { id: "planned_exec_need_approval", from: "PLANNED", event: "EXEC", to: "WAIT_APPROVAL", actions: ["set_pending"], effect: "REQUIRE_APPROVAL", priority: 60 },
      { id: "idle_exec_need_approval", from: "IDLE", event: "EXEC", to: "WAIT_APPROVAL", actions: ["set_pending"], effect: "REQUIRE_APPROVAL", priority: 50 },
    ]
  })()

  let matched: Record<string, unknown> | null = null
  for (const tr of transitions) {
    const fr = tr.from ?? "*"
    const ev = tr.event ?? "*"

    const fromOk = fr === "*" || (typeof fr === "string" && fr === currentState) || (Array.isArray(fr) && fr.includes(currentState))
    if (!fromOk) continue

    const evList = typeof ev === "string" ? [ev] : Array.isArray(ev) ? ev : ["*"]
    const evNorm = evList.filter((x): x is string => !!(typeof x === "string" && x.trim())).map((x) => x.toUpperCase())
    if (!evNorm.includes("*") && !evNorm.includes(event)) continue

    const guardName = tr.guard
    if (typeof guardName === "string" && guardName.trim()) {
      if (!_efsmGuard(guardName.trim(), plan, payload)) continue
    }

    matched = tr
    break
  }

  if (!matched) {
    return { allow: true, effect: "ALLOW", reason: "efsm: no transition", next_state: currentState, matched_transition: null, meta: null }
  }

  const toRaw = matched.to ?? "*"
  const nextState = toRaw === "*" || toRaw === null || toRaw === undefined
    ? currentState
    : String(toRaw).trim() || currentState

  const effectRaw = matched.effect ?? "ALLOW"
  const effect: string = typeof effectRaw === "string" ? effectRaw.trim().toUpperCase() : "ALLOW"
  const validEffects = new Set(["ALLOW", "BLOCK", "WARN", "LOG_ONLY", "REQUIRE_APPROVAL", "TRANSFORM"])
  const finalEffect = validEffects.has(effect) ? effect : "ALLOW"

  _efsmApplyActions(matched.actions, vars_, plan, payload)

  const allow = new Set(["ALLOW", "WARN", "LOG_ONLY", "TRANSFORM"]).has(finalEffect)
  const matchedId = typeof matched.id === "string" ? matched.id : "transition"
  let reason = `efsm: ${finalEffect.toLowerCase()} via ${matchedId}`
  if (finalEffect === "BLOCK") {
    reason = `efsm: blocked via ${matchedId}`
  }

  return {
    allow,
    effect: finalEffect,
    reason,
    next_state: nextState,
    matched_transition: typeof matched.id === "string" ? matched.id : null,
    meta: { from: currentState, to: nextState, event },
  }
}

function _efsmReplayHistory(
  instructions: Record<string, unknown>[],
  cfg: Record<string, unknown>,
): [string, Record<string, unknown>, PlanState] {
  const efsmCfg = _safeDict(cfg.efsm)
  const initial = (() => {
    const v = efsmCfg.initial
    return typeof v === "string" && v.trim() ? v.trim() : "IDLE"
  })()

  let state = initial
  const vars_: Record<string, unknown> = {}
  const plan = _buildPlanState(instructions, cfg)

  if (!efsmCfg.enabled) return [state, vars_, plan]

  for (const ins of instructions) {
    let event = _safeUpper(ins.instruction_type)
    if (!event) continue

    const payload: Record<string, unknown> = { event }
    const content = ins.content

    if (new Set(["READ", "WRITE", "EXEC"]).has(event) && content !== null && typeof content === "object" && !Array.isArray(content)) {
      const c = content as Record<string, unknown>
      const tool = c.tool_name
      const args = c.arguments

      if (typeof tool === "string" && tool.trim()) {
        const toolNorm = tool.trim()
        payload.tool = toolNorm
        event = _toolToInstructionType(toolNorm, cfg)
        payload.event = event
      }

      if (args !== null && typeof args === "object" && !Array.isArray(args)) {
        payload.args = args
      }
    }

    const step = _efsmStep(cfg, state, vars_, plan, event, payload)
    state = step.next_state

    if (event === "PLAN") {
      const idx = instructions.indexOf(ins)
      if (idx >= 0) {
        Object.assign(plan, _buildPlanState(instructions.slice(0, idx + 1), cfg))
      }
    }
  }

  return [state, vars_, plan]
}

export class EFSMPolicy extends Policy {
  private cfg: Record<string, unknown>

  constructor(cfg: Record<string, unknown> = {}) {
    super()
    this.cfg = cfg
  }

  async check(
    instructions: Record<string, unknown>[],
    currentResponse: Record<string, unknown>,
    latestInstructions: Record<string, unknown>[],
    traceId: string,
  ): Promise<PolicyCheckResult> {
    const efsmCfg = _safeDict(this.cfg.efsm)
    if (!efsmCfg.enabled) {
      return {
        modified: false,
        response: currentResponse,
        error_type: null,
        inactivate_error_type: null,
        policy_names: [],
        policy_sources: {},
      }
    }

    const response = { ...currentResponse }
    const toolCalls = extractToolCalls(response)
    if (!toolCalls.length) {
      return {
        modified: false,
        response: currentResponse,
        error_type: null,
        inactivate_error_type: null,
        policy_names: [],
        policy_sources: {},
      }
    }

    const [history, latest] = _splitHistoryAndLatest(instructions, latestInstructions)
    let [state, vars_, plan] = _efsmReplayHistory(history, this.cfg)

    const latestByToolCallId = new Map<string, Record<string, unknown>>()
    for (const ins of latest || []) {
      const content = ins.content
      if (content !== null && typeof content === "object" && !Array.isArray(content)) {
        const tcid = (content as Record<string, unknown>).tool_call_id
        if (typeof tcid === "string" && tcid) {
          latestByToolCallId.set(tcid, ins)
        }
      }
    }

    const errors: string[] = []
    const kept: Record<string, unknown>[] = []

    for (const tc of toolCalls) {
      const { toolName, toolCallId, argsDict, wasJsonStr } = parseToolCall(tc)

      const it = _toolToInstructionType(toolName, this.cfg)

      let cat: string | null = null
      if (toolCallId && latestByToolCallId.has(toolCallId)) {
        const _cat = latestByToolCallId.get(toolCallId)!.instruction_category
        cat = typeof _cat === "string" ? _cat : null
      }
      if (!cat) {
        cat = _instructionTypeToCategory(it)
      }

      const opId = _computeOpId(traceId, toolName, argsDict)

      const payload: Record<string, unknown> = {
        event: it,
        tool: toolName,
        args: argsDict,
        category: cat,
        op_id: opId,
      }

      const currentStateBefore = state
      const step = _efsmStep(this.cfg, state, vars_, plan, it, payload)
      state = step.next_state

      if (step.effect === "REQUIRE_APPROVAL") {
        const msg = `efsm: action requires approval (event=${it}, scope=${toolName})`
        const friendlyMsg = _friendlyApprovalMessage(toolName, it, currentStateBefore, msg)
        errors.push(friendlyMsg)
        continue
      }

      if (!step.allow) {
        const friendlyMsg = _friendlyEfsmBlockMessage(toolName, it, currentStateBefore, step.reason)
        errors.push(friendlyMsg)
        continue
      }

      kept.push(writeBackToolArgs(tc, argsDict, wasJsonStr))
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
