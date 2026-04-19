import { existsSync } from "node:fs"
import type { SIAgentsConfig } from "../types/config.ts"
import { ConfigLoader } from "./loader.ts"
import { expandPath } from "../utils/path.ts"

export interface FileSystemWatcher {
  close(): void
}

export class ConfigWatcher {
  private path: string
  private callback: (config: SIAgentsConfig) => void
  private watcher: FileSystemWatcher | null = null
  private debounceTimer: Timer | null = null
  private debounceMs: number

  constructor(
    path: string,
    callback: (config: SIAgentsConfig) => void,
    debounceMs: number = 100
  ) {
    this.path = expandPath(path)
    this.callback = callback
    this.debounceMs = debounceMs
  }

  start(): void {
    if (!existsSync(this.path)) {
      throw new Error(`Config file not found: ${this.path}`)
    }
    this.watch()
  }

  stop(): void {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer)
      this.debounceTimer = null
    }
    if (this.watcher) {
      this.watcher.close()
      this.watcher = null
    }
  }

  private async watch(): Promise<void> {
    const { watch } = await import("node:fs")
    this.watcher = watch(this.path, (eventType) => {
      if (eventType === "change") {
        this.handleFileChange()
      }
    }) as unknown as FileSystemWatcher
  }

  private handleFileChange(): void {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer)
    }
    this.debounceTimer = setTimeout(async () => {
      try {
        const config = await ConfigLoader.load(this.path)
        this.callback(config)
      } catch (error) {
        console.error(`Failed to reload config: ${error}`)
      }
    }, this.debounceMs)
  }
}

export class MultiConfigWatcher {
  private watchers: Map<string, ConfigWatcher> = new Map()
  private callback: (configs: Record<string, SIAgentsConfig>) => void
  private configs: Record<string, SIAgentsConfig> = {}

  constructor(callback: (configs: Record<string, SIAgentsConfig>) => void) {
    this.callback = callback
  }

  add(name: string, path: string): void {
    if (this.watchers.has(name)) {
      this.watchers.get(name)?.stop()
    }
    const watcher = new ConfigWatcher(path, (config) => {
      this.configs[name] = config
      this.callback({ ...this.configs })
    })
    watcher.start()
    this.watchers.set(name, watcher)
  }

  remove(name: string): void {
    const watcher = this.watchers.get(name)
    if (watcher) {
      watcher.stop()
      this.watchers.delete(name)
      delete this.configs[name]
    }
  }

  stopAll(): void {
    for (const watcher of this.watchers.values()) {
      watcher.stop()
    }
    this.watchers.clear()
    this.configs = {}
  }
}
