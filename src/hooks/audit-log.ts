import type { AfterToolContext } from "../types/hooks.ts"
import type { ToolCall } from "../types/instruction.ts"
import * as fs from "node:fs"
import * as path from "node:path"

export interface AuditLogHookConfig {
  traceId: string
  logDir: string
}

export interface AuditLogEntry {
  timestamp: string
  trace_id: string
  tool_name: string
  tool_call_id: string
  arguments: Record<string, unknown>
  result?: string
  exit_code?: number
  execution_time_ms?: number
  work_dir: string
  iteration: number
}

export function createAuditLogHook(config: AuditLogHookConfig): (ctx: AfterToolContext) => Promise<void> {
  return async (ctx: AfterToolContext): Promise<void> => {
    const startTime = Date.now()
    
    const logEntry: AuditLogEntry = {
      timestamp: new Date().toISOString(),
      trace_id: config.traceId,
      tool_name: ctx.toolCall.tool_name,
      tool_call_id: ctx.toolCall.tool_call_id,
      arguments: ctx.toolCall.arguments,
      result: ctx.toolCall.result,
      work_dir: ctx.workDir,
      iteration: ctx.iteration,
    }
    
    if (ctx.toolCall.result) {
      logEntry.exit_code = determineExitCode(ctx.toolCall)
    }
    
    logEntry.execution_time_ms = Date.now() - startTime
    
    await writeAuditLog(config.logDir, config.traceId, logEntry)
  }
}

function determineExitCode(toolCall: ToolCall): number {
  if (!toolCall.result) {
    return -1
  }
  
  const result = toolCall.result.toLowerCase()
  
  if (result.includes("error") || result.includes("failed") || result.includes("exception")) {
    return 1
  }
  
  if (result.includes("success") || result.includes("completed") || result.includes("ok")) {
    return 0
  }
  
  return 0
}

async function writeAuditLog(logDir: string, traceId: string, entry: AuditLogEntry): Promise<void> {
  try {
    await fs.promises.mkdir(logDir, { recursive: true })
    
    const logFileName = `audit-${traceId}.jsonl`
    const logPath = path.join(logDir, logFileName)
    
    const logLine = JSON.stringify(entry) + "\n"
    
    await fs.promises.appendFile(logPath, logLine, "utf-8")
  } catch (error) {
    console.error(`Failed to write audit log: ${error}`)
  }
}
