import type { SecurityType } from "../types/instruction.ts"

export const OPENCLAW_TOOL_ALIASES: Record<string, string> = {
  read: "read",
  read_file: "read",
  write: "write",
  write_file: "write",
  edit: "edit",
  edit_file: "edit",
  patch: "edit",
  exec: "exec",
  terminal: "exec",
  web_fetch: "web_fetch",
  web_search: "web_search",
  session_status: "session_status",
  sessions_list: "sessions_list",
  sessions_history: "sessions_history",
  sessions_send: "sessions_send",
  sessions_spawn: "sessions_spawn",
  memory_get: "memory_get",
  memory_search: "memory_search",
  image: "image",
  browser: "browser",
  browser_navigate: "browser",
  browser_click: "browser",
  browser_type: "browser",
  browser_press: "browser",
  browser_scroll: "browser",
  browser_back: "browser",
  browser_forward: "browser",
  browser_snapshot: "browser",
  browser_screenshot: "browser",
  browser_console: "browser",
  browser_get_images: "browser",
  browser_vision: "browser",
  process: "process",
  message: "message",
  tts: "tts",
  agents_list: "agents_list",
}

export interface OpenClawToolCall {
  id: string
  name: string
  arguments: string | Record<string, unknown>
}

export interface ParsedToolCall {
  name: string
  args: Record<string, unknown>
  canonicalName: string
}

export function parseOpenClawToolCall(toolCall: OpenClawToolCall): ParsedToolCall {
  const name = toolCall.name ?? ""
  let args: Record<string, unknown> = {}

  if (typeof toolCall.arguments === "string") {
    try {
      args = JSON.parse(toolCall.arguments)
    } catch {
      args = {}
    }
  } else if (typeof toolCall.arguments === "object" && toolCall.arguments !== null) {
    args = toolCall.arguments
  }

  const canonicalName = OPENCLAW_TOOL_ALIASES[name] ?? name

  return {
    name,
    args,
    canonicalName,
  }
}

export function getOpenClawToolSecurityAttributes(
  toolName: string,
  args: Record<string, unknown>
): Partial<SecurityType> {
  const canonicalName = OPENCLAW_TOOL_ALIASES[toolName] ?? toolName

  switch (canonicalName) {
    case "read":
    case "web_fetch":
    case "web_search":
      return {
        confidentiality: "LOW",
        trustworthiness: canonicalName === "read" ? "HIGH" : "LOW",
        confidence: "UNKNOWN",
        reversible: true,
        authority: "UNKNOWN",
      }

    case "write":
    case "edit":
      return {
        confidentiality: "UNKNOWN",
        trustworthiness: "UNKNOWN",
        confidence: "UNKNOWN",
        reversible: true,
        authority: "UNKNOWN",
      }

    case "exec":
      return {
        confidentiality: "LOW",
        trustworthiness: "HIGH",
        confidence: "UNKNOWN",
        reversible: false,
        authority: "UNKNOWN",
      }

    case "sessions_send":
    case "sessions_spawn":
      return {
        confidentiality: "HIGH",
        trustworthiness: "LOW",
        confidence: "UNKNOWN",
        reversible: false,
        authority: "UNKNOWN",
      }

    case "sessions_list":
    case "sessions_history":
    case "session_status":
    case "memory_get":
    case "memory_search":
    case "agents_list":
      return {
        confidentiality: "HIGH",
        trustworthiness: "HIGH",
        confidence: "UNKNOWN",
        reversible: true,
        authority: "UNKNOWN",
      }

    case "browser":
      return getBrowserSecurityAttributes(args)

    case "message":
      return {
        confidentiality: "HIGH",
        trustworthiness: "HIGH",
        confidence: "UNKNOWN",
        reversible: false,
        authority: "UNKNOWN",
      }

    case "tts":
      return {
        confidentiality: "LOW",
        trustworthiness: "HIGH",
        confidence: "UNKNOWN",
        reversible: false,
        authority: "UNKNOWN",
      }

    case "process":
      return getProcessSecurityAttributes(args)

    default:
      return {
        confidentiality: "UNKNOWN",
        trustworthiness: "UNKNOWN",
        confidence: "UNKNOWN",
        reversible: false,
        authority: "UNKNOWN",
      }
  }
}

function getBrowserSecurityAttributes(args: Record<string, unknown>): Partial<SecurityType> {
  const action = String(args.action ?? "")
  const readActions = new Set([
    "status",
    "profiles",
    "tabs",
    "snapshot",
    "screenshot",
    "console",
    "pdf",
  ])

  if (readActions.has(action)) {
    return {
      confidentiality: "UNKNOWN",
      trustworthiness: "LOW",
      confidence: "UNKNOWN",
      reversible: true,
      authority: "UNKNOWN",
    }
  }

  return {
    confidentiality: "LOW",
    trustworthiness: "LOW",
    confidence: "UNKNOWN",
    reversible: false,
    authority: "UNKNOWN",
  }
}

function getProcessSecurityAttributes(args: Record<string, unknown>): Partial<SecurityType> {
  const action = String(args.action ?? "")

  if (action === "list" || action === "log") {
    return {
      confidentiality: "HIGH",
      trustworthiness: "HIGH",
      confidence: "UNKNOWN",
      reversible: true,
      authority: "UNKNOWN",
    }
  }

  if (action === "poll") {
    return {
      confidentiality: "LOW",
      trustworthiness: "HIGH",
      confidence: "UNKNOWN",
      reversible: true,
      authority: "UNKNOWN",
    }
  }

  return {
    confidentiality: "LOW",
    trustworthiness: "HIGH",
    confidence: "UNKNOWN",
    reversible: false,
    authority: "UNKNOWN",
  }
}

export function extractPathFromToolCall(
  toolName: string,
  args: Record<string, unknown>
): string | null {
  const canonicalName = OPENCLAW_TOOL_ALIASES[toolName] ?? toolName

  switch (canonicalName) {
    case "read":
    case "write":
    case "edit":
      return extractPathArg(args)

    case "exec":
      return extractExecPath(args)

    default:
      return null
  }
}

function extractPathArg(args: Record<string, unknown>): string | null {
  const pathKeys = ["path", "file_path", "filePath", "filename", "file"]
  for (const key of pathKeys) {
    if (typeof args[key] === "string") {
      return args[key] as string
    }
  }
  return null
}

function extractExecPath(args: Record<string, unknown>): string | null {
  if (typeof args.command === "string") {
    const parts = (args.command as string).split(" ")
    return parts[0] ?? null
  }
  if (typeof args.cmd === "string") {
    const parts = (args.cmd as string).split(" ")
    return parts[0] ?? null
  }
  if (Array.isArray(args.command) && args.command.length > 0) {
    return String(args.command[0])
  }
  return null
}

export function isHighRiskTool(toolName: string): boolean {
  const canonicalName = OPENCLAW_TOOL_ALIASES[toolName] ?? toolName
  const highRiskTools = new Set([
    "exec",
    "write",
    "edit",
    "sessions_spawn",
    "sessions_send",
  ])
  return highRiskTools.has(canonicalName)
}

export function isReadOnlyTool(toolName: string): boolean {
  const canonicalName = OPENCLAW_TOOL_ALIASES[toolName] ?? toolName
  const readOnlyTools = new Set([
    "read",
    "web_fetch",
    "web_search",
    "sessions_list",
    "sessions_history",
    "session_status",
    "memory_get",
    "memory_search",
    "agents_list",
  ])
  return readOnlyTools.has(canonicalName)
}
