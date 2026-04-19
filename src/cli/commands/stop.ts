import { unlink } from "node:fs/promises"
import { getPidFilePath, readPidFile, isProcessRunning } from "../../utils/pid.ts"

async function deletePidFile(): Promise<void> {
  const pidFile = getPidFilePath()
  try {
    await unlink(pidFile)
  } catch {
    // ignore
  }
}

async function waitForProcessExit(pid: number, timeoutMs: number): Promise<boolean> {
  const startTime = Date.now()
  while (Date.now() - startTime < timeoutMs) {
    if (!isProcessRunning(pid)) {
      return true
    }
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  return false
}

export async function stopCommand(): Promise<void> {
  const pidData = await readPidFile()

  if (!pidData) {
    console.log("服务未运行 (未找到 PID 文件)")
    process.exit(0)
  }

  const { pid, port, host } = pidData

  if (!isProcessRunning(pid)) {
    console.log("服务未运行 (进程不存在)")
    await deletePidFile()
    process.exit(0)
  }

  console.log(`正在停止服务 (PID: ${pid}, 地址: ${host}:${port})...`)

  try {
    process.kill(pid, "SIGTERM")
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e)
    console.error(`发送停止信号失败: ${message}`)
    process.exit(1)
  }

  const exited = await waitForProcessExit(pid, 30000)

  if (!exited) {
    console.log("服务未在超时时间内停止，尝试强制终止...")
    try {
      process.kill(pid, "SIGKILL")
    } catch {
      // ignore
    }
    await new Promise((resolve) => setTimeout(resolve, 1000))
  }

  await deletePidFile()

  if (isProcessRunning(pid)) {
    console.error("无法停止服务")
    process.exit(1)
  }

  console.log("服务已停止")
}
