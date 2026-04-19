export type CLICommand = "start" | "stop" | "status" | "config" | "run" | "optimize"

export interface CLIOptions {
  config?: string
  port?: number
  host?: string
  verbose?: boolean
  daemon?: boolean
}

export interface StartOptions extends CLIOptions {
  model?: string
  policy?: string
}

export interface RunOptions extends CLIOptions {
  skill: string
  task: string
  workDir?: string
  adapter?: "bare-agent" | "openclaw"
  maxIterations?: number
}

export interface OptimizeOptions extends CLIOptions {
  skill: string
  rounds?: number
  targetModel?: string
}

export interface ConfigOptions extends CLIOptions {
  action: "show" | "validate" | "import" | "init"
  policyPath?: string
  litellmPath?: string
}

export interface ServiceStatus {
  running: boolean
  pid?: number
  port?: number
  uptime?: number
  config?: string
  models?: string[]
  policyEnabled?: boolean
  taintEnabled?: boolean
}

export interface ParsedArgs {
  command: CLICommand
  options: Record<string, unknown>
  positional: string[]
}
