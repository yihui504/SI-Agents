import type { ToolAliasMap } from "../types/taint.ts"

const DEFAULT_ALIASES: Record<string, string> = {
  write_file: "write",
  edit_file: "edit",
  read_file: "read",
  list_directory: "read",
  spawn: "sessions_spawn",
  patch: "edit",
  terminal: "exec",
  execute_command: "exec",
  exec: "exec",
  cronjob: "cron",
  text_to_speech: "tts",
  session_search: "sessions_history",
  delegate_task: "sessions_spawn",
  vision_analyze: "image",
  browser_navigate: "browser",
  browser_click: "browser",
  browser_type: "browser",
  browser_press: "browser",
  browser_scroll: "browser",
  browser_back: "browser",
  browser_snapshot: "browser",
  browser_console: "browser",
  browser_get_images: "browser",
  browser_vision: "browser",
}

export class ToolAliasMapper {
  private aliases: Map<string, string>

  constructor(config?: ToolAliasMap) {
    this.aliases = new Map<string, string>()
    for (const [from, to] of Object.entries(DEFAULT_ALIASES)) {
      this.aliases.set(from, to)
    }
    if (config) {
      for (const [from, to] of Object.entries(config)) {
        this.aliases.set(from, to)
      }
    }
  }

  canonicalize(toolName: string): string {
    return this.aliases.get(toolName) ?? toolName
  }

  registerAlias(from: string, to: string): void {
    this.aliases.set(from, to)
  }

  loadFromConfig(config: ToolAliasMap): void {
    for (const [from, to] of Object.entries(config)) {
      this.aliases.set(from, to)
    }
  }

  getAll(): ReadonlyMap<string, string> {
    return this.aliases
  }
}
