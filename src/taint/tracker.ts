import { type Level, LEVEL_ORDER } from "../types/instruction.ts"
import { PathRegistry } from "./path-registry.ts"
import { ToolAliasMapper } from "./tool-aliases.ts"
import { computePropTaint, computePropTaintForInstruction } from "./propagation.ts"

const INPUT_TOOLS = new Set([
  "read", "web_fetch", "web_search", "session_status", "sessions_list",
  "sessions_history", "memory_search", "memory_get", "agents_list", "image",
])

const OUTPUT_TOOLS = new Set([
  "edit", "write", "exec", "message", "sessions_send", "sessions_spawn",
  "tts", "gateway",
])

const TOOLS_BY_ACTION: Record<string, { input_actions: string[]; output_actions: string[] }> = {
  browser: {
    input_actions: ["status", "start", "stop", "profiles", "tabs", "snapshot", "screenshot", "console", "pdf", "open"],
    output_actions: ["focus", "close", "navigate", "upload", "dialog", "act"],
  },
  process: {
    input_actions: ["list", "poll", "log"],
    output_actions: ["write", "send-keys", "submit", "paste", "kill"],
  },
  canvas: {
    input_actions: ["snapshot"],
    output_actions: ["present", "hide", "navigate", "eval", "a2ui_push", "a2ui_reset"],
  },
  nodes: {
    input_actions: ["status", "describe", "camera_snap", "camera_list", "camera_clip", "screen_record", "location_get"],
    output_actions: ["pending", "approve", "reject", "notify", "run", "invoke"],
  },
  cron: {
    input_actions: ["status", "list", "runs"],
    output_actions: ["add", "update", "remove", "run", "wake"],
  },
}

function classifyTool(toolName: string, args: Record<string, unknown>): "input" | "output" | "none" {
  const name = toolName.trim().toLowerCase()
  if (!name) return "none"

  if (name in TOOLS_BY_ACTION) {
    const cfg = TOOLS_BY_ACTION[name]
    const action = typeof args["action"] === "string" ? args["action"].trim().toLowerCase() : ""
    if (action) {
      if (cfg.output_actions.includes(action)) return "output"
      if (cfg.input_actions.includes(action)) return "input"
    }
    return "output"
  }

  if (OUTPUT_TOOLS.has(name)) return "output"
  if (INPUT_TOOLS.has(name)) return "input"
  return "none"
}

function extractPaths(args: Record<string, unknown>): string[] {
  const paths: string[] = []
  for (const key of ["path", "file_path", "directory", "dir", "dest", "destination", "source", "url"]) {
    const val = args[key]
    if (typeof val === "string" && val.trim()) paths.push(val.trim())
  }
  const cmd = args["command"]
  if (typeof cmd === "string") {
    const tokens = cmd.split(/\s+/)
    for (const token of tokens) {
      if (token.startsWith("/") || token.startsWith("~/") || token.startsWith("C:") || token.startsWith("D:")) {
        paths.push(token)
      }
    }
  }
  return paths
}

export class TaintTracker {
  private pathRegistry: PathRegistry
  private aliasMapper: ToolAliasMapper
  private propTaintCache: Map<string, { prop_trustworthiness: Level; prop_confidentiality: Level }>

  constructor(pathRegistry?: PathRegistry, aliasMapper?: ToolAliasMapper) {
    this.pathRegistry = pathRegistry ?? new PathRegistry()
    this.aliasMapper = aliasMapper ?? new ToolAliasMapper()
    this.propTaintCache = new Map()
  }

  setBaseTaint(
    instruction: Record<string, unknown>,
    toolName: string,
    args: Record<string, unknown>,
  ): void {
    const canonical = this.aliasMapper.canonicalize(toolName)
    const kind = classifyTool(canonical, args)
    const paths = extractPaths(args)

    let trustworthiness: Level = "UNKNOWN"
    let confidentiality: Level = "UNKNOWN"

    if (paths.length > 0) {
      trustworthiness = this.pathRegistry.classifyTrustworthiness(paths)
      confidentiality = this.pathRegistry.classifyConfidentiality(paths)
    }

    if (kind === "input") {
      if (trustworthiness === "UNKNOWN") trustworthiness = "MID"
      if (confidentiality === "UNKNOWN") confidentiality = "LOW"
    } else if (kind === "output") {
      if (trustworthiness === "UNKNOWN") trustworthiness = "MID"
      if (confidentiality === "UNKNOWN") confidentiality = "LOW"
    }

    const st = instruction["security_type"]
    if (typeof st === "object" && st !== null) {
      const sec = st as Record<string, unknown>
      sec["trustworthiness"] = trustworthiness
      sec["confidentiality"] = confidentiality
    } else {
      instruction["security_type"] = {
        confidentiality,
        trustworthiness,
        prop_confidentiality: "UNKNOWN",
        prop_trustworthiness: "UNKNOWN",
        confidence: "UNKNOWN",
        reversible: false,
        authority: "UNKNOWN",
        risk: "UNKNOWN",
        custom: {},
      }
    }
  }

  propagate(instructions: Record<string, unknown>[]): void {
    this.propTaintCache.clear()
    computePropTaint(instructions)
    for (const instr of instructions) {
      const id = instr["id"]
      if (typeof id === "string") {
        const st = instr["security_type"]
        if (typeof st === "object" && st !== null) {
          const sec = st as Record<string, unknown>
          this.propTaintCache.set(id, {
            prop_trustworthiness: (sec["prop_trustworthiness"] as Level) ?? "UNKNOWN",
            prop_confidentiality: (sec["prop_confidentiality"] as Level) ?? "UNKNOWN",
          })
        }
      }
    }
  }

  getPropTaint(instructionId: string): { prop_trustworthiness: Level; prop_confidentiality: Level } {
    return this.propTaintCache.get(instructionId) ?? {
      prop_trustworthiness: "UNKNOWN",
      prop_confidentiality: "UNKNOWN",
    }
  }

  checkTaintPolicy(
    toolName: string,
    args: Record<string, unknown>,
    securityType: Record<string, unknown>,
  ): { allowed: boolean; reason: string | null } {
    const canonical = this.aliasMapper.canonicalize(toolName)
    const kind = classifyTool(canonical, args)
    if (kind === "none") return { allowed: true, reason: null }

    const trust = (typeof securityType["trustworthiness"] === "string" && securityType["trustworthiness"] in LEVEL_ORDER)
      ? securityType["trustworthiness"] as Level
      : "UNKNOWN"
    const conf = (typeof securityType["confidentiality"] === "string" && securityType["confidentiality"] in LEVEL_ORDER)
      ? securityType["confidentiality"] as Level
      : "UNKNOWN"
    const propConf = (typeof securityType["prop_confidentiality"] === "string" && securityType["prop_confidentiality"] in LEVEL_ORDER)
      ? securityType["prop_confidentiality"] as Level
      : conf

    if (kind === "input") {
      const ok = LEVEL_ORDER[trust] >= LEVEL_ORDER[conf]
      return {
        allowed: ok,
        reason: ok ? null : `trustworthiness < confidentiality (${trust} < ${conf})`,
      }
    }

    const ok = LEVEL_ORDER[trust] >= LEVEL_ORDER[propConf]
    return {
      allowed: ok,
      reason: ok ? null : `trustworthiness < prop_confidentiality (${trust} < ${propConf})`,
    }
  }
}
