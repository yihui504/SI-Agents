import { readPidFile, isProcessRunning } from "../../utils/pid.ts"
import type { ServiceStatus } from "../types.ts"

async function fetchHealthEndpoint(host: string, port: number): Promise<Record<string, unknown> | null> {
  try {
    const response = await fetch(`http://${host}:${port}/health`, {
      method: "GET",
      signal: AbortSignal.timeout(5000),
    })
    if (response.ok) {
      return await response.json() as Record<string, unknown>
    }
    return null
  } catch {
    return null
  }
}

export async function statusCommand(): Promise<ServiceStatus> {
  const pidData = await readPidFile()

  if (!pidData) {
    const status: ServiceStatus = { running: false }
    console.log("服务状态: 未运行")
    console.log("  原因: 未找到 PID 文件")
    return status
  }

  const { pid, port, host, startTime } = pidData

  if (!isProcessRunning(pid)) {
    const status: ServiceStatus = { running: false }
    console.log("服务状态: 未运行")
    console.log("  原因: 进程不存在")
    return status
  }

  const health = await fetchHealthEndpoint(host, port)
  const uptime = Date.now() - startTime

  const status: ServiceStatus = {
    running: true,
    pid,
    port,
    uptime,
  }

  console.log("服务状态: 运行中")
  console.log(`  PID: ${pid}`)
  console.log(`  地址: http://${host}:${port}`)
  console.log(`  运行时间: ${Math.floor(uptime / 1000)} 秒`)

  if (health) {
    console.log(`  健康检查: 正常`)
    console.log(`  时间戳: ${health.timestamp ?? "未知"}`)
  } else {
    console.log(`  健康检查: 无响应`)
  }

  return status
}
