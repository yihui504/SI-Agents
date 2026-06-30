import { parseArgs } from "node:util"
import { readFile } from "node:fs/promises"
import { join, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import type { CLICommand, StartOptions, RunOptions, OptimizeOptions, ConfigOptions } from "./types.ts"
import { startCommand } from "./commands/start.ts"
import { stopCommand } from "./commands/stop.ts"
import { statusCommand } from "./commands/status.ts"
import { configCommand } from "./commands/config.ts"
import { runCommand } from "./commands/run.ts"
import { optimizeCommand } from "./commands/optimize.ts"

let VERSION = "0.1.0"

async function loadVersion(): Promise<string> {
  try {
    const currentDir = dirname(fileURLToPath(import.meta.url))
    const packagePath = join(currentDir, "..", "..", "package.json")
    const content = await readFile(packagePath, "utf-8")
    const pkg = JSON.parse(content)
    return pkg.version ?? "0.1.0"
  } catch {
    return "0.1.0"
  }
}

function printHelp(): void {
  console.log(`SI-Agents CLI v${VERSION}

用法:
  si-agents <command> [options]

命令:
  start     启动代理服务
  stop      停止代理服务
  status    查看服务状态
  config    配置管理
  run       运行技能任务
  optimize  优化技能

选项:
  --config <path>   配置文件路径
  --port <number>   服务端口
  --host <string>   服务地址
  --verbose         详细输出
  --help, -h        显示帮助信息
  --version, -v     显示版本信息

示例:
  si-agents start --config ./si-agents.config.json --port 4000
  si-agents start --daemon
  si-agents stop
  si-agents status
  si-agents config show
  si-agents config validate
  si-agents config init
  si-agents config import --policy ./policy.json --litellm ./litellm_config.yaml
  si-agents run --skill ./skills/my-skill --task "完成任务X" --adapter bare-agent
  si-agents optimize --skill ./skills/my-skill --rounds 5
`)
}

function printCommandHelp(command: CLICommand): void {
  switch (command) {
    case "start":
      console.log(`si-agents start - 启动代理服务

用法:
  si-agents start [options]

选项:
  --config <path>   配置文件路径
  --port <number>   服务端口 (默认: 4000)
  --host <string>   服务地址 (默认: 127.0.0.1)
  --model <string>  默认模型
  --policy <path>   策略配置文件
  --daemon          后台运行
  --verbose         详细输出

示例:
  si-agents start --config ./si-agents.config.json
  si-agents start --port 8080 --host 0.0.0.0
  si-agents start --daemon
`)
      break
    case "stop":
      console.log(`si-agents stop - 停止代理服务

用法:
  si-agents stop

示例:
  si-agents stop
`)
      break
    case "status":
      console.log(`si-agents status - 查看服务状态

用法:
  si-agents status

示例:
  si-agents status
`)
      break
    case "config":
      console.log(`si-agents config - 配置管理

用法:
  si-agents config <action> [options]

操作:
  show      显示当前配置
  validate  校验配置文件
  import    从 ArbiterOS policy.json 和 litellm_config.yaml 导入
  init      生成默认配置文件

选项:
  --config <path>      配置文件路径
  --policy <path>      ArbiterOS 策略文件路径 (用于 import)
  --litellm <path>     LiteLLM 配置文件路径 (用于 import)

示例:
  si-agents config show
  si-agents config validate
  si-agents config init
  si-agents config import --policy ./policy.json --litellm ./litellm_config.yaml
`)
      break
    case "run":
      console.log(`si-agents run - 运行技能任务

用法:
  si-agents run --skill <path> --task <description> [options]

选项:
  --skill <path>          技能目录路径 (必需)
  --task <description>    任务描述 (必需)
  --work-dir <path>       工作目录
  --adapter <name>        适配器类型: bare-agent | openclaw (实验性) (默认: bare-agent)
  --max-iterations <n>    最大迭代次数 (默认: 50)
  --config <path>         配置文件路径

示例:
  si-agents run --skill ./skills/my-skill --task "完成任务X"
  si-agents run --skill ./skills/my-skill --task "完成任务X" --adapter bare-agent
  si-agents run --skill ./skills/my-skill --task "完成任务X" --work-dir ./workspace
`)
      break
    case "optimize":
      console.log(`si-agents optimize - 优化技能

用法:
  si-agents optimize --skill <path> [options]

选项:
  --skill <path>        技能目录路径 (必需)
  --rounds <number>     优化轮次 (默认: 3)
  --target-model <name> 目标模型
  --config <path>       配置文件路径

示例:
  si-agents optimize --skill ./skills/my-skill
  si-agents optimize --skill ./skills/my-skill --rounds 5
  si-agents optimize --skill ./skills/my-skill --target-model gpt-4o
`)
      break
  }
}

function getStringValue(values: Record<string, string | boolean | undefined>, key: string): string | undefined {
  const val = values[key]
  return typeof val === "string" ? val : undefined
}

function getBooleanValue(values: Record<string, string | boolean | undefined>, key: string): boolean | undefined {
  const val = values[key]
  return typeof val === "boolean" ? val : undefined
}

export async function main(args: string[]): Promise<void> {
  VERSION = await loadVersion()

  if (args.length === 0) {
    printHelp()
    process.exit(0)
  }

  if (args[0] === "--help" || args[0] === "-h") {
    printHelp()
    process.exit(0)
  }

  if (args[0] === "--version" || args[0] === "-v") {
    console.log(`si-agents v${VERSION}`)
    process.exit(0)
  }

  const command = args[0] as CLICommand

  if (!["start", "stop", "status", "config", "run", "optimize"].includes(command)) {
    console.error(`未知命令: ${command}`)
    console.log("运行 'si-agents --help' 查看帮助信息")
    process.exit(1)
  }

  const commandArgs = args.slice(1)

  if (commandArgs.includes("--help") || commandArgs.includes("-h")) {
    printCommandHelp(command)
    process.exit(0)
  }

  try {
    switch (command) {
      case "start": {
        const { values } = parseArgs({
          args: commandArgs,
          options: {
            config: { type: "string", short: "c" },
            port: { type: "string" },
            host: { type: "string" },
            model: { type: "string" },
            policy: { type: "string" },
            daemon: { type: "boolean", short: "d" },
            verbose: { type: "boolean", short: "V" },
          },
          strict: false,
        })

        const portStr = getStringValue(values, "port")
        const options: StartOptions = {
          config: getStringValue(values, "config"),
          port: portStr ? parseInt(portStr, 10) : undefined,
          host: getStringValue(values, "host"),
          model: getStringValue(values, "model"),
          policy: getStringValue(values, "policy"),
          daemon: getBooleanValue(values, "daemon"),
          verbose: getBooleanValue(values, "verbose"),
        }

        await startCommand(options)
        break
      }

      case "stop": {
        await stopCommand()
        break
      }

      case "status": {
        await statusCommand()
        break
      }

      case "config": {
        const action = commandArgs[0] as ConfigOptions["action"]
        if (!action || !["show", "validate", "import", "init"].includes(action)) {
          console.error(`未知操作: ${action ?? "(未指定)"}`)
          console.log("运行 'si-agents config --help' 查看帮助信息")
          process.exit(1)
        }

        const { values } = parseArgs({
          args: commandArgs.slice(1),
          options: {
            config: { type: "string", short: "c" },
            policy: { type: "string" },
            litellm: { type: "string" },
          },
          strict: false,
        })

        const options: ConfigOptions = {
          action,
          config: getStringValue(values, "config"),
          policyPath: getStringValue(values, "policy"),
          litellmPath: getStringValue(values, "litellm"),
        }

        await configCommand(options)
        break
      }

      case "run": {
        const { values } = parseArgs({
          args: commandArgs,
          options: {
            skill: { type: "string" },
            task: { type: "string" },
            "work-dir": { type: "string" },
            adapter: { type: "string" },
            "max-iterations": { type: "string" },
            config: { type: "string", short: "c" },
          },
          strict: false,
        })

        const skill = getStringValue(values, "skill")
        const task = getStringValue(values, "task")
        const maxIterStr = getStringValue(values, "max-iterations")

        if (!skill) {
          console.error("错误: 必须指定 --skill 参数")
          process.exit(1)
        }
        if (!task) {
          console.error("错误: 必须指定 --task 参数")
          process.exit(1)
        }

        const options: RunOptions = {
          skill,
          task,
          workDir: getStringValue(values, "work-dir"),
          adapter: getStringValue(values, "adapter") as RunOptions["adapter"],
          maxIterations: maxIterStr ? parseInt(maxIterStr, 10) : undefined,
          config: getStringValue(values, "config"),
        }

        await runCommand(options)
        break
      }

      case "optimize": {
        const { values } = parseArgs({
          args: commandArgs,
          options: {
            skill: { type: "string" },
            rounds: { type: "string" },
            "target-model": { type: "string" },
            config: { type: "string", short: "c" },
          },
          strict: false,
        })

        const skill = getStringValue(values, "skill")
        const roundsStr = getStringValue(values, "rounds")

        if (!skill) {
          console.error("错误: 必须指定 --skill 参数")
          process.exit(1)
        }

        const options: OptimizeOptions = {
          skill,
          rounds: roundsStr ? parseInt(roundsStr, 10) : undefined,
          targetModel: getStringValue(values, "target-model"),
          config: getStringValue(values, "config"),
        }

        await optimizeCommand(options)
        break
      }
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e)
    console.error(`错误: ${message}`)
    if (args.includes("--verbose")) {
      console.error(e)
    }
    process.exit(1)
  }
}
