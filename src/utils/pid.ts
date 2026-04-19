import { homedir } from "node:os"
import { join } from "node:path"
import { readFile } from "node:fs/promises"
import { existsSync } from "node:fs"

export interface PidFileData {
  pid: number
  port: number
  host: string
  configPath?: string
  startTime: number
}

export function getPidFilePath(): string {
  return join(homedir(), ".skvm", "si-agents.pid")
}

export async function readPidFile(): Promise<PidFileData | null> {
  const pidFile = getPidFilePath()
  if (!existsSync(pidFile)) {
    return null
  }
  try {
    const content = await readFile(pidFile, "utf-8")
    return JSON.parse(content)
  } catch {
    return null
  }
}

export function isProcessRunning(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}
