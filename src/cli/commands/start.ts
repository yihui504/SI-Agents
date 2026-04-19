import { homedir } from "node:os"
import { join } from "node:path"
import { mkdir, writeFile, readFile, unlink } from "node:fs/promises"
import { existsSync } from "node:fs"
import type { StartOptions } from "../types.ts"
import { ConfigLoader } from "../../config/loader.ts"
import { PolicyRegistry } from "../../policy/registry.ts"
import { TaintTracker } from "../../taint/tracker.ts"
import { LangfuseClient } from "../../langfuse/client.ts"
import { ProxyServer, createProxyServer } from "../../proxy/server.ts"
import type { SIAgentsConfig } from "../../types/config.ts"
import { expandPath } from "../../utils/path.ts"

function getPidFilePath(): string {
  return join(homedir(), ".skvm", "si-agents.pid")
}

function getLogDir(): string {
  return join(homedir(), ".skvm", "logs")
}

async function ensureDirs(): Promise<void> {
  const skvmDir = join(homedir(), ".skvm")
  const logDir = getLogDir()
  if (!existsSync(skvmDir)) {
    await mkdir(skvmDir, { recursive: true })
  }
  if (!existsSync(logDir)) {
    await mkdir(logDir, { recursive: true })
  }
}

async function writePidFile(pid: number, config: SIAgentsConfig): Promise<void> {
  const pidFile = getPidFilePath()
  const data = {
    pid,
    port: config.server.port,
    host: config.server.host,
    configPath: config.skvm.cache_dir,
    startTime: Date.now(),
  }
  await writeFile(pidFile, JSON.stringify(data, null, 2))
}

async function checkAlreadyRunning(): Promise<{ running: boolean; pid?: number }> {
  const pidFile = getPidFilePath()
  if (!existsSync(pidFile)) {
    return { running: false }
  }
  try {
    const content = await readFile(pidFile, "utf-8")
    const data = JSON.parse(content)
    const pid = data.pid
    if (typeof pid !== "number") {
      return { running: false }
    }
    try {
      process.kill(pid, 0)
      return { running: true, pid }
    } catch {
      await unlink(pidFile)
      return { running: false }
    }
  } catch {
    return { running: false }
  }
}

async function initializeSubsystems(config: SIAgentsConfig): Promise<{
  policyRegistry: PolicyRegistry
  taintTracker: TaintTracker
  langfuseClient: LangfuseClient | null
}> {
  const policyRegistry = new PolicyRegistry()
  const taintTracker = new TaintTracker()
  let langfuseClient: LangfuseClient | null = null

  if (config.langfuse?.public_key && config.langfuse?.secret_key) {
    langfuseClient = new LangfuseClient({
      publicKey: config.langfuse.public_key,
      secretKey: config.langfuse.secret_key,
      baseUrl: config.langfuse.base_url,
    })
  }

  return { policyRegistry, taintTracker, langfuseClient }
}

function setupGracefulShutdown(
  server: ProxyServer,
  langfuseClient: LangfuseClient | null,
  pidFile: string
): void {
  let isShuttingDown = false

  const shutdown = async () => {
    if (isShuttingDown) return
    isShuttingDown = true

    console.log("\n正在关闭服务...")

    server.stop()

    if (langfuseClient) {
      await langfuseClient.shutdown()
    }

    try {
      await unlink(pidFile)
    } catch {
      // ignore
    }

    console.log("服务已停止")
    process.exit(0)
  }

  process.on("SIGINT", shutdown)
  process.on("SIGTERM", shutdown)
}

export async function startCommand(options: StartOptions): Promise<void> {
  const configPath = options.config ?? ConfigLoader.getDefaultConfigPath()

  if (!existsSync(expandPath(configPath))) {
    console.error(`配置文件不存在: ${configPath}`)
    console.log("请先运行 'si-agents config init' 创建配置文件")
    process.exit(1)
  }

  const runningCheck = await checkAlreadyRunning()
  if (runningCheck.running) {
    console.error(`服务已在运行中 (PID: ${runningCheck.pid})`)
    process.exit(1)
  }

  await ensureDirs()

  let config: SIAgentsConfig
  try {
    config = await ConfigLoader.loadWithEnv(configPath)
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e)
    console.error(`加载配置失败: ${message}`)
    process.exit(1)
  }

  if (options.port !== undefined) {
    config.server.port = options.port
  }
  if (options.host !== undefined) {
    config.server.host = options.host
  }

  console.log(`正在加载配置: ${configPath}`)

  const { policyRegistry, taintTracker, langfuseClient } = await initializeSubsystems(config)

  const server = createProxyServer(config, policyRegistry, taintTracker)

  if (options.daemon) {
    console.log("守护进程模式启动中...")
    const logFile = join(getLogDir(), "si-agents.log")
    const logFd = await Bun.file(logFile).exists() ? Bun.file(logFile).writer() : null

    const originalLog = console.log
    const originalError = console.error

    if (logFd) {
      console.log = (...args) => {
        const msg = `[${new Date().toISOString()}] ${args.join(" ")}\n`
        logFd.write(msg)
      }
      console.error = (...args) => {
        const msg = `[${new Date().toISOString()}] ERROR: ${args.join(" ")}\n`
        logFd.write(msg)
      }
    }
  }

  server.start()

  await writePidFile(process.pid, config)

  const pidFile = getPidFilePath()
  setupGracefulShutdown(server, langfuseClient, pidFile)

  console.log(`SI-Agents 服务已启动`)
  console.log(`  地址: http://${config.server.host}:${config.server.port}`)
  console.log(`  PID: ${process.pid}`)
  console.log(`  策略引擎: ${config.policy.enabled ? "已启用" : "已禁用"}`)
  console.log(`  污点追踪: ${config.taint.enabled ? "已启用" : "已禁用"}`)
  console.log(`  Langfuse: ${langfuseClient?.isEnabled() ? "已启用" : "已禁用"}`)

  if (!options.daemon) {
    console.log("\n按 Ctrl+C 停止服务")
    await new Promise(() => {})
  }
}
