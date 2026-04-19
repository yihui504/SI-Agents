import type {
  InstructionType,
  InstructionCategory,
  SecurityType,
} from "../types/instruction.ts"

export interface ToolParseResult {
  instructionType: InstructionType
  instructionCategory: InstructionCategory
  securityType: Partial<SecurityType>
}

export const INSTRUCTION_TYPE_TO_CATEGORY: Record<string, InstructionCategory> = {
  REASON: "COGNITIVE.Reasoning",
  PLAN: "COGNITIVE.Reasoning",
  CRITIQUE: "COGNITIVE.Reasoning",
  STORE: "MEMORY.Management",
  RETRIEVE: "MEMORY.Management",
  COMPRESS: "MEMORY.Management",
  PRUNE: "MEMORY.Management",
  READ: "EXECUTION.Env",
  WRITE: "EXECUTION.Env",
  EXEC: "EXECUTION.Env",
  WAIT: "EXECUTION.Env",
  ASK: "EXECUTION.Human",
  RESPOND: "EXECUTION.Human",
  USER_MESSAGE: "EXECUTION.Human",
  HANDOFF: "EXECUTION.Agent",
  DELEGATE: "EXECUTION.Agent",
  SUBSCRIBE: "EXECUTION.Perception",
  RECEIVE: "EXECUTION.Perception",
}

type ToolParser = (args: Record<string, unknown>) => ToolParseResult

function makeResult(
  instructionType: InstructionType,
  securityType: Partial<SecurityType>
): ToolParseResult {
  return {
    instructionType,
    instructionCategory:
      INSTRUCTION_TYPE_TO_CATEGORY[instructionType] ?? "EXECUTION.Env",
    securityType,
  }
}

const DEFAULT_RESULT: ToolParseResult = makeResult("EXEC", {
  confidentiality: "UNKNOWN",
  trustworthiness: "UNKNOWN",
  confidence: "UNKNOWN",
  reversible: false,
  authority: "UNKNOWN",
})

function parseOpenClawRead(args: Record<string, unknown>): ToolParseResult {
  return makeResult("READ", {
    confidentiality: "LOW",
    trustworthiness: "HIGH",
    confidence: "UNKNOWN",
    reversible: true,
    authority: "UNKNOWN",
  })
}

function parseOpenClawWrite(args: Record<string, unknown>): ToolParseResult {
  return makeResult("WRITE", {
    confidentiality: "UNKNOWN",
    trustworthiness: "UNKNOWN",
    confidence: "UNKNOWN",
    reversible: true,
    authority: "UNKNOWN",
  })
}

function parseOpenClawExec(args: Record<string, unknown>): ToolParseResult {
  return makeResult("EXEC", {
    confidentiality: "LOW",
    trustworthiness: "HIGH",
    confidence: "UNKNOWN",
    reversible: false,
    authority: "UNKNOWN",
  })
}

function parseOpenClawExternalRead(args: Record<string, unknown>): ToolParseResult {
  return makeResult("READ", {
    confidentiality: "LOW",
    trustworthiness: "LOW",
    confidence: "UNKNOWN",
    reversible: true,
    authority: "UNKNOWN",
  })
}

function parseOpenClawDelegate(args: Record<string, unknown>): ToolParseResult {
  return makeResult("DELEGATE", {
    confidentiality: "HIGH",
    trustworthiness: "LOW",
    confidence: "UNKNOWN",
    reversible: false,
    authority: "UNKNOWN",
  })
}

function parseOpenClawRespond(args: Record<string, unknown>): ToolParseResult {
  return makeResult("RESPOND", {
    confidentiality: "LOW",
    trustworthiness: "HIGH",
    confidence: "UNKNOWN",
    reversible: false,
    authority: "UNKNOWN",
  })
}

const BROWSER_READ_ACTIONS = new Set([
  "status",
  "profiles",
  "tabs",
  "snapshot",
  "screenshot",
  "console",
  "pdf",
])

const BROWSER_READ_SUFFIXES = new Set([
  "snapshot",
  "screenshot",
  "console",
  "get_images",
  "vision",
])

const BROWSER_EXEC_SUFFIXES = new Set([
  "navigate",
  "click",
  "type",
  "press",
  "scroll",
  "back",
  "forward",
])

function parseOpenClawBrowser(args: Record<string, unknown>): ToolParseResult {
  const action = String(args.action ?? "")
  if (BROWSER_READ_ACTIONS.has(action)) {
    return makeResult("READ", {
      confidentiality: "UNKNOWN",
      trustworthiness: "LOW",
      confidence: "UNKNOWN",
      reversible: true,
      authority: "UNKNOWN",
    })
  }
  return makeResult("EXEC", {
    confidentiality: "LOW",
    trustworthiness: "LOW",
    confidence: "UNKNOWN",
    reversible: false,
    authority: "UNKNOWN",
  })
}

function parseOpenClawBrowserRead(args: Record<string, unknown>): ToolParseResult {
  return makeResult("READ", {
    confidentiality: "UNKNOWN",
    trustworthiness: "LOW",
    confidence: "UNKNOWN",
    reversible: true,
    authority: "UNKNOWN",
  })
}

function parseOpenClawBrowserExec(args: Record<string, unknown>): ToolParseResult {
  return makeResult("EXEC", {
    confidentiality: "LOW",
    trustworthiness: "LOW",
    confidence: "UNKNOWN",
    reversible: false,
    authority: "UNKNOWN",
  })
}

function parseOpenClawProcess(args: Record<string, unknown>): ToolParseResult {
  const action = String(args.action ?? "")
  if (action === "list" || action === "log") {
    return makeResult("READ", {
      confidentiality: "HIGH",
      trustworthiness: "HIGH",
      confidence: "UNKNOWN",
      reversible: true,
      authority: "UNKNOWN",
    })
  }
  if (action === "poll") {
    return makeResult("WAIT", {
      confidentiality: "LOW",
      trustworthiness: "HIGH",
      confidence: "UNKNOWN",
      reversible: true,
      authority: "UNKNOWN",
    })
  }
  return makeResult("EXEC", {
    confidentiality: "LOW",
    trustworthiness: "HIGH",
    confidence: "UNKNOWN",
    reversible: false,
    authority: "UNKNOWN",
  })
}

function parseOpenClawMessage(args: Record<string, unknown>): ToolParseResult {
  return makeResult("RESPOND", {
    confidentiality: "HIGH",
    trustworthiness: "HIGH",
    confidence: "UNKNOWN",
    reversible: false,
    authority: "UNKNOWN",
  })
}

function parseOpenClawTts(args: Record<string, unknown>): ToolParseResult {
  return makeResult("RESPOND", {
    confidentiality: "LOW",
    trustworthiness: "HIGH",
    confidence: "UNKNOWN",
    reversible: false,
    authority: "UNKNOWN",
  })
}

function parseOpenClawRetrieve(args: Record<string, unknown>): ToolParseResult {
  return makeResult("RETRIEVE", {
    confidentiality: "HIGH",
    trustworthiness: "HIGH",
    confidence: "UNKNOWN",
    reversible: true,
    authority: "UNKNOWN",
  })
}

function parseOpenClawStore(args: Record<string, unknown>): ToolParseResult {
  return makeResult("STORE", {
    confidentiality: "HIGH",
    trustworthiness: "HIGH",
    confidence: "UNKNOWN",
    reversible: true,
    authority: "UNKNOWN",
  })
}

const OPENCLAW_TOOL_PARSER_REGISTRY: Record<string, ToolParser> = {
  read: parseOpenClawRead,
  read_file: parseOpenClawRead,
  write: parseOpenClawWrite,
  write_file: parseOpenClawWrite,
  edit: parseOpenClawWrite,
  edit_file: parseOpenClawWrite,
  patch: parseOpenClawWrite,
  exec: parseOpenClawExec,
  terminal: parseOpenClawExec,
  process: parseOpenClawProcess,
  web_fetch: parseOpenClawExternalRead,
  web_search: parseOpenClawExternalRead,
  sessions_send: parseOpenClawDelegate,
  sessions_spawn: parseOpenClawDelegate,
  message: parseOpenClawMessage,
  tts: parseOpenClawTts,
  browser: parseOpenClawBrowser,
  agents_list: parseOpenClawRetrieve,
  sessions_list: parseOpenClawRetrieve,
  sessions_history: parseOpenClawRetrieve,
  session_status: parseOpenClawRetrieve,
  memory_search: parseOpenClawRetrieve,
  memory_get: parseOpenClawRetrieve,
  browser_navigate: parseOpenClawBrowserExec,
  browser_click: parseOpenClawBrowserExec,
  browser_type: parseOpenClawBrowserExec,
  browser_press: parseOpenClawBrowserExec,
  browser_scroll: parseOpenClawBrowserExec,
  browser_back: parseOpenClawBrowserExec,
  browser_forward: parseOpenClawBrowserExec,
  browser_snapshot: parseOpenClawBrowserRead,
  browser_screenshot: parseOpenClawBrowserRead,
  browser_console: parseOpenClawBrowserRead,
  browser_get_images: parseOpenClawBrowserRead,
  browser_vision: parseOpenClawBrowserRead,
}

function parseBareRead(args: Record<string, unknown>): ToolParseResult {
  return makeResult("READ", {
    confidentiality: "LOW",
    trustworthiness: "HIGH",
    confidence: "UNKNOWN",
    reversible: true,
    authority: "UNKNOWN",
  })
}

function parseBareWrite(args: Record<string, unknown>): ToolParseResult {
  return makeResult("WRITE", {
    confidentiality: "UNKNOWN",
    trustworthiness: "UNKNOWN",
    confidence: "UNKNOWN",
    reversible: true,
    authority: "UNKNOWN",
  })
}

function parseBareExec(args: Record<string, unknown>): ToolParseResult {
  return makeResult("EXEC", {
    confidentiality: "LOW",
    trustworthiness: "HIGH",
    confidence: "UNKNOWN",
    reversible: false,
    authority: "UNKNOWN",
  })
}

const BARE_AGENT_TOOL_PARSER_REGISTRY: Record<string, ToolParser> = {
  read_file: parseBareRead,
  write_file: parseBareWrite,
  execute_command: parseBareExec,
  list_directory: parseBareRead,
  web_fetch: parseOpenClawExternalRead,
}

function parseBrowserByPrefix(
  toolName: string,
  args: Record<string, unknown>
): ToolParseResult {
  const suffix = toolName.slice("browser_".length)
  if (BROWSER_READ_SUFFIXES.has(suffix)) {
    return parseOpenClawBrowserRead(args)
  }
  return parseOpenClawBrowserExec(args)
}

export function parseToolInstruction(
  toolName: string,
  args: Record<string, unknown>,
  agent: "openclaw" | "bare_agent" = "openclaw"
): ToolParseResult {
  const registry =
    agent === "bare_agent"
      ? BARE_AGENT_TOOL_PARSER_REGISTRY
      : OPENCLAW_TOOL_PARSER_REGISTRY

  const parser = registry[toolName]
  if (parser) return parser(args)

  if (agent === "openclaw" && toolName.startsWith("browser_")) {
    return parseBrowserByPrefix(toolName, args)
  }

  return { ...DEFAULT_RESULT }
}

export { OPENCLAW_TOOL_PARSER_REGISTRY, BARE_AGENT_TOOL_PARSER_REGISTRY }
