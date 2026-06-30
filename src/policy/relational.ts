import type { PolicyCheckResult } from "../types/policy.ts"
import { Policy } from "./policy.ts"
import {
  _safeStr,
  _safeUpper,
  _safeLevel,
  _levelRank,
  _levelAtLeast,
  _levelMax,
  _safeDict,
  _softSourceConf,
  extractToolCalls,
  parseToolCall,
  writeBackToolArgs,
  _appendUniqueError,
  _getPrimaryPathHint,
  _extractInstructionSecurity,
  _sourceLevels,
  DEFAULT_RULE_DETAILS_URL,
} from "./policy-utils.ts"

const BROWSER_READ_ACTIONS = new Set(["status", "profiles", "tabs", "snapshot", "screenshot", "console", "pdf"])
const BROWSER_LOW_RISK_ACTIONS = new Set(["dialog"])
const BROWSER_SIDE_EFFECT_ACTIONS = new Set(["open", "focus", "close", "navigate", "upload", "act"])
const PROCESS_READ_ACTIONS = new Set(["list", "poll", "log"])
const CRON_READ_ACTIONS = new Set(["status", "list", "runs"])
const CRON_PERSIST_ACTIONS = new Set(["add", "update", "remove", "run", "wake"])
const GATEWAY_READ_ACTIONS = new Set(["config.get", "config.schema"])
const GATEWAY_WRITE_ACTIONS = new Set(["config.apply", "config.patch"])
const CANVAS_READ_ACTIONS = new Set(["snapshot"])
const NODES_READ_ACTIONS = new Set(["status", "describe", "camera_snap", "camera_list", "camera_clip", "screen_record", "location_get"])
const MESSAGE_EDIT_ACTIONS = new Set(["edit"])

const SHARED_OR_EXPORTED_PATH_HINTS = [
  "/shared/", "/public/", "/publish/", "/published/",
  "/export/", "/exports/", "/outbox/", "/upload/",
  "/uploads/", "/dist/", "/artifacts/", "/release/",
  "/releases/", "/www/", "/tmp/",
]

function _looksExternalRef(v: string): boolean {
  const s = _safeStr(v).toLowerCase()
  return s.startsWith("http://") || s.startsWith("https://")
}

function _looksSharedOrExportedSink(pathHint: string): boolean {
  const p = _safeStr(pathHint).toLowerCase()
  if (!p) return false
  return SHARED_OR_EXPORTED_PATH_HINTS.some((h) => p.includes(h))
}

const SSRF_RISK_PATTERNS = [
  /^https?:\/\/169\.254\.169\.254/i,
  /^https?:\/\/169\.254\./i,
  /^https?:\/\/10\./i,
  /^https?:\/\/172\.(1[6-9]|2[0-9]|3[01])\./i,
  /^https?:\/\/192\.168\./i,
  /^https?:\/\/127\./i,
  /^https?:\/\/0\./i,
  /^https?:\/\/localhost/i,
  /^https?:\/\/\[::1\]/i,
  /^https?:\/\/fc00:/i,
  /^https?:\/\/fe80:/i,
  /^https?:\/\/metadata\.google/i,
  /^https?:\/\/metadata\.azure/i,
]

function _looksSsrfRisk(url: string): boolean {
  const s = _safeStr(url)
  if (!s) return false
  return SSRF_RISK_PATTERNS.some(p => p.test(s))
}

function _flowKind(
  toolName: string,
  argsDict: Record<string, unknown>,
  sec: Record<string, unknown>,
): string {
  const name = _safeStr(toolName).toLowerCase()
  const action = _safeStr(argsDict.action).toLowerCase()
  const itype = _safeUpper(sec.instruction_type)

  if (!name) return "none"

  if (new Set(["session_status", "sessions_list", "agents_list"]).has(name)) return "read_state"
  if (name === "process" && PROCESS_READ_ACTIONS.has(action)) return "read_state"
  if (name === "cron" && CRON_READ_ACTIONS.has(action)) return "read_state"
  if (name === "canvas" && CANVAS_READ_ACTIONS.has(action)) return "read_state"

  if (name === "browser") {
    if (BROWSER_READ_ACTIONS.has(action)) return "read_external"
    if (BROWSER_LOW_RISK_ACTIONS.has(action)) return "read_state"
    if (BROWSER_SIDE_EFFECT_ACTIONS.has(action)) return "ui_side_effect"
  }
  if (name === "web_fetch") {
    const url = _safeStr(argsDict.url || argsDict.uri || argsDict.path || "")
    if (_looksSsrfRisk(url)) return "ssrf_risk"
    return "read_external"
  }
  if (name === "web_search") return "read_external"
  if (name === "image") {
    const imageSrc = _safeStr(argsDict.image || argsDict.path)
    return _looksExternalRef(imageSrc) ? "read_external" : "read_sensitive"
  }

  if (name === "nodes") {
    if (NODES_READ_ACTIONS.has(action)) return "read_sensitive"
    return "exec_side_effect"
  }

  if (name === "gateway") {
    if (GATEWAY_READ_ACTIONS.has(action)) return "read_sensitive"
    if (GATEWAY_WRITE_ACTIONS.has(action)) return "write_local"
    return "exec_side_effect"
  }

  if (new Set(["sessions_send", "sessions_spawn"]).has(name) || itype === "DELEGATE") return "delegate_sink"

  if (name === "message") {
    if (MESSAGE_EDIT_ACTIONS.has(action)) return "write_local"
    return "comm_sink"
  }
  if (name === "tts") return "voice_sink"

  if (name === "cron" && CRON_PERSIST_ACTIONS.has(action)) return "persist_side_effect"

  if (new Set(["read", "read_file", "list_directory", "memory_search", "memory_get", "sessions_history"]).has(name)) return "read_sensitive"
  if (new Set(["READ", "RETRIEVE"]).has(itype)) return "read_sensitive"

  if (new Set(["write", "write_file", "edit"]).has(name) || new Set(["WRITE", "STORE"]).has(itype)) {
    const pathHint = _getPrimaryPathHint(argsDict)
    if (_looksSharedOrExportedSink(pathHint)) return "write_shared"
    return "write_local"
  }

  if (new Set(["WAIT", "ASK"]).has(itype)) return "read_state"

  if (new Set(["exec", "execute_command", "process"]).has(name) || itype === "EXEC") return "exec_side_effect"

  return "none"
}

function _flowLabel(flowKind: string): string {
  const labels: Record<string, string> = {
    read_external: "读取外部信息",
    read_sensitive: "读取敏感信息",
    read_state: "读取状态信息",
    write_local: "本地写入/落盘",
    write_shared: "共享/导出写入",
    delegate_sink: "委托/跨会话发送",
    comm_sink: "对外发送/可见输出",
    voice_sink: "语音输出",
    ui_side_effect: "UI 控制副作用",
    exec_side_effect: "执行类副作用",
    persist_side_effect: "持久化副作用",
    respond_sink: "直接回复输出",
    ssrf_risk: "SSRF 风险请求",
  }
  return labels[flowKind] || flowKind || "unknown"
}

function _renderToolInstructionBlock(toolName: string, argsDict: Record<string, unknown>): string {
  if (toolName === "exec" || toolName === "process") {
    const command = _safeStr(argsDict.command || argsDict.cmd || argsDict.script)
    if (command) return `\`\`\`bash\n${command}\n\`\`\``
  }
  return "```json\n" + JSON.stringify(argsDict, null, 2) + "\n```"
}

function _relationalPolicyTitle(flowKind: string): string {
  const mapping: Record<string, string> = {
    read_external: "外部内容读取",
    read_sensitive: "敏感信息读取",
    read_state: "状态读取",
    write_local: "本地写入",
    write_shared: "共享或导出写入",
    delegate_sink: "跨会话委托",
    comm_sink: "对外发送",
    voice_sink: "语音输出",
    ui_side_effect: "界面操作",
    exec_side_effect: "执行类动作",
    persist_side_effect: "持久化任务",
    respond_sink: "直接回复输出",
    ssrf_risk: "SSRF 风险请求",
  }
  return mapping[flowKind] || "关系型安全保护"
}

function _relationalPolicyFunctionText(flowKind: string): string {
  const mapping: Record<string, string> = {
    read_external: "这一步会读取外部内容，但当前条件下系统无法确认这种读取是安全的，因此先拦截。",
    read_sensitive: "这一步会读取较敏感的信息，但当前读取方暂不满足安全要求，因此先拦截。",
    read_state: "这一步会读取系统状态，但当前依据还不足以支持继续读取，因此先拦截。",
    write_local: "这一步会把内容写入本地位置，但当前内容不适合直接落盘，因此先拦截。",
    write_shared: "这一步会把内容写入更容易扩散的位置，因此先拦截。",
    delegate_sink: "这一步会把内容或任务交给其他会话或代理，但当前承接对象暂不满足安全要求，因此先拦截。",
    comm_sink: "这一步会把内容发送到对外可见的渠道，但当前接收对象可能不够可信，因此先拦截。",
    voice_sink: "这一步会把内容直接以语音形式输出，内容一旦播出更难控制，因此先拦截。",
    ui_side_effect: "这一步会直接影响界面或交互环境，但驱动它的依据还不够可靠，因此先拦截。",
    exec_side_effect: "这一步会直接影响系统或运行环境，但驱动它的依据还不够可靠，因此先拦截。",
    persist_side_effect: "这一步会把动作固化为持续生效的任务，但当前条件下不适合直接持久化，因此先拦截。",
    respond_sink: "当前内容不适合直接展示给用户，因此先拦截。",
    ssrf_risk: "这一步会请求内部或元数据服务地址，可能泄露云环境敏感信息，因此先拦截。",
  }
  return mapping[flowKind] || "当前信息流转方式存在安全风险，因此先拦截。"
}

function _relationalRuleReference(flowKind: string, url: string): string {
  return [
    `- 规则类型：${_relationalPolicyTitle(flowKind)}`,
    "- 保护目标：避免不够可信或不适合外发的内容继续流向当前目标。",
    `- 详情见：${url}`,
  ].join("\n")
}

function _friendlyMessage(
  toolName: string,
  flowKind: string,
  argsDict: Record<string, unknown>,
  url: string,
): string {
  return [
    "## ⚠️ 安全策略拦截确认",
    "",
    "### 1. 触发指令",
    _renderToolInstructionBlock(toolName, argsDict),
    "",
    "### 2. 拦截说明",
    `[${_relationalPolicyTitle(flowKind)}]：${_relationalPolicyFunctionText(flowKind)}`,
    "",
    "### 3. 规则说明",
    _relationalRuleReference(flowKind, url),
  ].join("\n")
}

function _friendlyRespondMessage(url: string): string {
  const flowKind = "respond_sink"
  return [
    "## ⚠️ 安全策略拦截确认",
    "",
    "### 1. 触发指令",
    "```text\nRESPOND\n```",
    "",
    "### 2. 拦截说明",
    `[${_relationalPolicyTitle(flowKind)}]：${_relationalPolicyFunctionText(flowKind)}`,
    "",
    "### 3. 规则说明",
    _relationalRuleReference(flowKind, url),
  ].join("\n")
}

function _evaluateFlow(
  flowKind: string,
  sec: Record<string, unknown>,
  argsDict: Record<string, unknown>,
  currentTaintStatus: Record<string, unknown> | null = null,
): [boolean, string, string, Record<string, unknown>] {
  const [sourceTrust, sourceConf] = _sourceLevels(sec, currentTaintStatus)
  const sinkTrust = _safeLevel(sec.trustworthiness)
  const conf = _safeLevel(sec.confidentiality)
  const risk = _safeUpper(sec.risk, "UNKNOWN")

  const extra: Record<string, unknown> = {
    flow_kind: flowKind,
    source_trustworthiness: sourceTrust,
    source_confidentiality: sourceConf,
    sink_trustworthiness: sinkTrust,
    instruction_confidentiality: conf,
    prop_confidentiality: _safeLevel(sec.prop_confidentiality),
    risk,
    instruction_type: _safeUpper(sec.instruction_type),
    instruction_category: _safeStr(sec.instruction_category),
    authority: _safeUpper(sec.authority, "UNKNOWN"),
    confidence: _safeLevel(sec.confidence),
    reversible: !!sec.reversible,
    custom: sec.custom || {},
    action: _safeStr(argsDict.action),
    path_hint: _getPrimaryPathHint(argsDict),
  }

  if (flowKind === "read_external") {
    const actual = _levelMax(sinkTrust, "LOW")
    const required = "LOW"
    return [_levelAtLeast(actual, required), actual, required, extra]
  }

  if (flowKind === "read_sensitive") {
    const actual = sinkTrust
    const required = conf
    return [_levelAtLeast(actual, required), actual, required, extra]
  }

  if (flowKind === "read_state") {
    return [true, sourceTrust, "LOW", extra]
  }

  if (flowKind === "write_local") {
    const pathHint = _getPrimaryPathHint(argsDict)
    if (pathHint && !_looksSharedOrExportedSink(pathHint) && !_looksExternalRef(pathHint)) {
      const actual = _levelMax(sinkTrust, "HIGH")
      const required = _softSourceConf(sourceConf)
      return [_levelAtLeast(actual, required), actual, required, extra]
    }
    const actual = sinkTrust
    const required = sourceConf
    return [_levelAtLeast(actual, required), actual, required, extra]
  }

  if (flowKind === "write_shared") {
    const actual = "UNKNOWN"
    const required = _levelMax(_softSourceConf(sourceConf), "UNKNOWN")
    return [_levelAtLeast(actual, required), actual, required, extra]
  }

  if (flowKind === "delegate_sink") {
    const actual = "LOW"
    const required = _softSourceConf(sourceConf)
    return [_levelAtLeast(actual, required), actual, required, extra]
  }

  if (flowKind === "comm_sink") {
    const actual = "UNKNOWN"
    const required = _softSourceConf(sourceConf)
    return [_levelAtLeast(actual, required), actual, required, extra]
  }

  if (flowKind === "voice_sink") {
    const actual = "LOW"
    const required = _softSourceConf(sourceConf)
    return [_levelAtLeast(actual, required), actual, required, extra]
  }

  if (flowKind === "ui_side_effect") {
    const actual = sourceTrust
    let required = "MID"
    if (sourceConf === "HIGH" || risk === "HIGH" || risk === "CRITICAL") {
      required = "HIGH"
    }
    return [_levelAtLeast(actual, required), actual, required, extra]
  }

  if (flowKind === "exec_side_effect") {
    const actual = sourceTrust
    let required = "MID"
    if (sourceConf === "HIGH" || risk === "HIGH" || risk === "CRITICAL") {
      required = "HIGH"
    }
    return [_levelAtLeast(actual, required), actual, required, extra]
  }

  if (flowKind === "persist_side_effect") {
    const actual = sourceTrust
    if (sourceConf === "MID" || sourceConf === "HIGH") {
      return [false, actual, sourceConf, extra]
    }
    const required = "MID"
    return [_levelAtLeast(actual, required), actual, required, extra]
  }

  if (flowKind === "ssrf_risk") {
    return [false, "UNKNOWN", "HIGH", extra]
  }

  return [true, sourceTrust, "LOW", extra]
}

export class RelationalPolicy extends Policy {
  private cfg: Record<string, unknown>
  private ruleDetailsUrl: string

  constructor(cfg: Record<string, unknown> = {}) {
    super()
    this.cfg = cfg
    const topLevel = _safeStr(cfg.rule_details_url)
    const taintLevel = _safeStr(_safeDict(cfg.taint).rule_details_url)
    this.ruleDetailsUrl = topLevel || taintLevel || DEFAULT_RULE_DETAILS_URL
  }

  async check(
    instructions: Record<string, unknown>[],
    currentResponse: Record<string, unknown>,
    latestInstructions: Record<string, unknown>[],
    traceId: string,
  ): Promise<PolicyCheckResult> {
    const response = { ...currentResponse }
    const toolCalls = extractToolCalls(response)
    const taintCfg = _safeDict(this.cfg.taint)
    const tpCfg = _safeDict(taintCfg.taint_policy)

    const instrByToolCallId = new Map<string, Record<string, unknown>>()
    for (const ins of latestInstructions || []) {
      const content = ins.content
      if (!content || typeof content !== "object" || Array.isArray(content)) continue
      const tcid = (content as Record<string, unknown>).tool_call_id
      if (typeof tcid === "string" && tcid) {
        instrByToolCallId.set(tcid, ins)
      }
    }

    const errors: string[] = []
    const seenErrors = new Set<string>()
    const kept: Record<string, unknown>[] = []

    for (const tc of toolCalls) {
      const { toolName, toolCallId, argsDict, wasJsonStr } = parseToolCall(tc)
      const ins = instrByToolCallId.get(toolCallId || "")
      const sec = _extractInstructionSecurity(ins || {})
      const flowKind = _flowKind(toolName, argsDict, sec)

      if (flowKind === "none") {
        kept.push(writeBackToolArgs(tc, argsDict, wasJsonStr))
        continue
      }

      if (!ins && tpCfg.fail_closed_on_missing_instruction_metadata) {
        const userMessage = _friendlyMessage(toolName, flowKind, argsDict, this.ruleDetailsUrl)
        _appendUniqueError(errors, seenErrors, userMessage)
        continue
      }

      const [ok, actual, required] = _evaluateFlow(flowKind, sec, argsDict)

      if (ok) {
        kept.push(writeBackToolArgs(tc, argsDict, wasJsonStr))
        continue
      }

      const userMessage = _friendlyMessage(toolName, flowKind, argsDict, this.ruleDetailsUrl)
      _appendUniqueError(errors, seenErrors, userMessage)
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
    const shouldTreatRespondAsSink = !!tpCfg.treat_respond_as_sink || !!tpCfg.respond_as_output
    const respondInstructionEnabled = (() => {
      const sinks = tpCfg.instruction_sinks
      if (Array.isArray(sinks) && sinks.length > 0) {
        return sinks.some((x: unknown) => typeof x === "string" && _safeUpper(x) === "RESPOND")
      }
      return true
    })()

    if (typeof content === "string" && content.trim() && shouldTreatRespondAsSink && respondInstructionEnabled) {
      let respondIns: Record<string, unknown> | undefined
      for (let i = (latestInstructions || []).length - 1; i >= 0; i--) {
        if (_safeUpper(latestInstructions[i].instruction_type) === "RESPOND") {
          respondIns = latestInstructions[i]
          break
        }
      }

      const sec = _extractInstructionSecurity(respondIns || {})
      const [sourceTrust, sourceConf] = _sourceLevels(sec)

      if (!respondIns && tpCfg.fail_closed_on_missing_instruction_metadata) {
        const userMsg = _friendlyRespondMessage(this.ruleDetailsUrl)
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

      const actual = "UNKNOWN"
      const required = _softSourceConf(sourceConf)

      if (!_levelAtLeast(actual, required)) {
        const userMsg = _friendlyRespondMessage(this.ruleDetailsUrl)
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
