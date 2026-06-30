import { existsSync, readFileSync, writeFileSync, mkdirSync, unlinkSync, readdirSync } from "node:fs"
import { join } from "node:path"

export interface FileStoreConfig {
  dir: string
  enabled: boolean
}

export class FileStore {
  private config: FileStoreConfig

  constructor(config: FileStoreConfig) {
    this.config = config
    if (this.config.enabled) {
      mkdirSync(this.config.dir, { recursive: true })
    }
  }

  isEnabled(): boolean {
    return this.config.enabled
  }

  save(key: string, data: Record<string, unknown>): void {
    if (!this.config.enabled) return
    const filePath = this.getFilePath(key)
    writeFileSync(filePath, JSON.stringify(data), "utf-8")
  }

  load(key: string): Record<string, unknown> | null {
    if (!this.config.enabled) return null
    const filePath = this.getFilePath(key)
    if (!existsSync(filePath)) return null
    try {
      const content = readFileSync(filePath, "utf-8")
      return JSON.parse(content)
    } catch {
      return null
    }
  }

  delete(key: string): boolean {
    if (!this.config.enabled) return false
    const filePath = this.getFilePath(key)
    if (!existsSync(filePath)) return false
    try {
      unlinkSync(filePath)
      return true
    } catch {
      return false
    }
  }

  list(): string[] {
    if (!this.config.enabled) return []
    try {
      return readdirSync(this.config.dir)
        .filter(f => f.endsWith(".json"))
        .map(f => f.replace(/\.json$/, ""))
    } catch {
      return []
    }
  }

  private getFilePath(key: string): string {
    const safeKey = key.replace(/[^a-zA-Z0-9_-]/g, "_")
    return join(this.config.dir, `${safeKey}.json`)
  }
}
