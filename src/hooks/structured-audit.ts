import { createWriteStream, type WriteStream } from "node:fs"

export type AuditSeverity = "info" | "warn" | "error" | "critical"

export interface AuditEvent {
  timestamp: string
  severity: AuditSeverity
  category: string
  action: string
  traceId?: string
  policyName?: string
  message: string
  details?: Record<string, unknown>
}

export type AuditOutput = "console" | "file" | "webhook"

export interface AuditLoggerConfig {
  outputs: AuditOutput[]
  filePath?: string
  webhookUrl?: string
  minSeverity?: AuditSeverity
}

const SEVERITY_ORDER: Record<AuditSeverity, number> = {
  info: 0,
  warn: 1,
  error: 2,
  critical: 3,
}

export class AuditLogger {
  private config: AuditLoggerConfig
  private fileStream: WriteStream | null = null

  constructor(config: AuditLoggerConfig) {
    this.config = config
    if (config.outputs.includes("file") && config.filePath) {
      this.fileStream = createWriteStream(config.filePath, { flags: "a" })
    }
  }

  log(event: Omit<AuditEvent, "timestamp">): void {
    const fullEvent: AuditEvent = {
      ...event,
      timestamp: new Date().toISOString(),
    }
    const minSeverity = this.config.minSeverity ?? "info"
    if (SEVERITY_ORDER[fullEvent.severity] < SEVERITY_ORDER[minSeverity]) return

    for (const output of this.config.outputs) {
      switch (output) {
        case "console":
          console.log(JSON.stringify(fullEvent))
          break
        case "file":
          this.fileStream?.write(JSON.stringify(fullEvent) + "\n")
          break
        case "webhook":
          this.sendWebhook(fullEvent)
          break
      }
    }
  }

  info(category: string, action: string, message: string, details?: Record<string, unknown>): void {
    this.log({ severity: "info", category, action, message, details })
  }

  warn(category: string, action: string, message: string, details?: Record<string, unknown>): void {
    this.log({ severity: "warn", category, action, message, details })
  }

  error(category: string, action: string, message: string, details?: Record<string, unknown>): void {
    this.log({ severity: "error", category, action, message, details })
  }

  critical(category: string, action: string, message: string, details?: Record<string, unknown>): void {
    this.log({ severity: "critical", category, action, message, details })
  }

  private async sendWebhook(event: AuditEvent): Promise<void> {
    if (!this.config.webhookUrl) return
    try {
      await fetch(this.config.webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(event),
      })
    } catch {}
  }

  destroy(): void {
    this.fileStream?.end()
    this.fileStream = null
  }
}

let defaultLogger: AuditLogger | null = null

export function getDefaultAuditLogger(): AuditLogger | null {
  return defaultLogger
}

export function setDefaultAuditLogger(logger: AuditLogger | null): void {
  if (defaultLogger) defaultLogger.destroy()
  defaultLogger = logger
}

export function audit(event: Omit<AuditEvent, "timestamp">): void {
  if (defaultLogger) {
    defaultLogger.log(event)
  }
}
