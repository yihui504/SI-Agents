import { join, dirname } from "node:path"
import { readFile, writeFile, mkdir } from "node:fs/promises"
import { existsSync } from "node:fs"
import type { ConfigOptions } from "../types.ts"
import { ConfigLoader, DEFAULT_CONFIG } from "../../config/index.ts"
import { PolicyImporter } from "../../config/policy-import.ts"
import { LiteLLMImporter } from "../../config/litellm-import.ts"
import type { SIAgentsConfig } from "../../types/config.ts"
import { expandPath } from "../../utils/path.ts"

const SENSITIVE_KEY_PATTERNS = [
  /api[_-]?key/i,
  /secret/i,
  /password/i,
  /token/i,
  /credential/i,
  /private[_-]?key/i,
]

function redactSensitiveFields(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj
  if (typeof obj === "string") return obj
  if (Array.isArray(obj)) return obj.map(redactSensitiveFields)
  if (typeof obj === "object") {
    const result: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      if (SENSITIVE_KEY_PATTERNS.some((p) => p.test(key)) && typeof value === "string") {
        result[key] = value ? "***REDACTED***" : value
      } else {
        result[key] = redactSensitiveFields(value)
      }
    }
    return result
  }
  return obj
}

async function showConfig(configPath: string): Promise<void> {
  const expandedPath = expandPath(configPath)
  if (!existsSync(expandedPath)) {
    console.error(`配置文件不存在: ${expandedPath}`)
    process.exit(1)
  }

  try {
    const content = await readFile(expandedPath, "utf-8")
    const config = JSON.parse(content)
    console.log(JSON.stringify(redactSensitiveFields(config), null, 2))
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e)
    console.error(`读取配置文件失败: ${message}`)
    process.exit(1)
  }
}

async function validateConfig(configPath: string): Promise<void> {
  const expandedPath = expandPath(configPath)
  if (!existsSync(expandedPath)) {
    console.error(`配置文件不存在: ${expandedPath}`)
    process.exit(1)
  }

  try {
    const config = await ConfigLoader.load(expandedPath)
    console.log("配置文件校验通过")
    console.log(`  服务端口: ${config.server.port}`)
    console.log(`  服务地址: ${config.server.host}`)
    console.log(`  模型路由数: ${config.models.routes.length}`)
    console.log(`  策略引擎: ${config.policy.enabled ? "已启用" : "已禁用"}`)
    console.log(`  污点追踪: ${config.taint.enabled ? "已启用" : "已禁用"}`)
    if (config.models.default) {
      console.log(`  默认模型: ${config.models.default}`)
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e)
    console.error(`配置校验失败: ${message}`)
    process.exit(1)
  }
}

async function initConfig(configPath: string): Promise<void> {
  const expandedPath = expandPath(configPath)

  if (existsSync(expandedPath)) {
    console.error(`配置文件已存在: ${expandedPath}`)
    process.exit(1)
  }

  const config: SIAgentsConfig = {
    ...DEFAULT_CONFIG,
    models: {
      routes: [
        {
          name: "default",
          provider: "openai",
          api_base: "https://api.openai.com/v1",
          api_key: "${OPENAI_API_KEY}",
          model_id: "gpt-4o",
        },
      ],
      default: "default",
    },
  }

  const dir = dirname(expandedPath)
  if (!existsSync(dir)) {
    await mkdir(dir, { recursive: true })
  }

  await writeFile(expandedPath, JSON.stringify(config, null, 2))
  console.log(`配置文件已创建: ${expandedPath}`)
  console.log("\n请编辑配置文件，设置正确的 API 密钥和模型信息")
}

async function importConfig(options: ConfigOptions): Promise<void> {
  const configPath = options.config ?? ConfigLoader.getDefaultConfigPath()
  const expandedPath = expandPath(configPath)

  const config: SIAgentsConfig = { ...DEFAULT_CONFIG }

  if (options.policyPath) {
    try {
      const policyConfig = await PolicyImporter.fromArbiterOS(options.policyPath)
      console.log(`已导入策略配置: ${options.policyPath}`)
      config.policy = {
        enabled: policyConfig.enabled,
        observe_only: policyConfig.observe_only,
        config_path: options.policyPath,
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e)
      console.error(`导入策略配置失败: ${message}`)
    }
  }

  if (options.litellmPath) {
    try {
      const modelRoutes = await LiteLLMImporter.importModelRoutes(options.litellmPath)
      console.log(`已导入 LiteLLM 配置: ${options.litellmPath}`)
      config.models.routes = modelRoutes
      if (modelRoutes.length > 0) {
        config.models.default = modelRoutes[0]!.name
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e)
      console.error(`导入 LiteLLM 配置失败: ${message}`)
    }
  }

  const dir = dirname(expandedPath)
  if (!existsSync(dir)) {
    await mkdir(dir, { recursive: true })
  }

  await writeFile(expandedPath, JSON.stringify(config, null, 2))
  console.log(`配置文件已创建: ${expandedPath}`)
}

export async function configCommand(options: ConfigOptions): Promise<void> {
  const configPath = options.config ?? ConfigLoader.getDefaultConfigPath()

  switch (options.action) {
    case "show":
      await showConfig(configPath)
      break
    case "validate":
      await validateConfig(configPath)
      break
    case "init":
      await initConfig(configPath)
      break
    case "import":
      await importConfig(options)
      break
    default:
      console.error(`未知操作: ${options.action}`)
      process.exit(1)
  }
}
