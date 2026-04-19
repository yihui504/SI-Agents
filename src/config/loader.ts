import { existsSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { SIAgentsConfigSchema, type SIAgentsConfig } from "../types/config.ts"
import { DEFAULT_CONFIG } from "./defaults.ts"
import { expandPath } from "../utils/path.ts"

function deepMerge<T extends Record<string, unknown>>(target: T, source: Partial<T>): T {
  const result = { ...target }
  for (const key of Object.keys(source) as (keyof T)[]) {
    const sourceValue = source[key]
    const targetValue = result[key]
    if (
      sourceValue !== undefined &&
      sourceValue !== null &&
      typeof sourceValue === "object" &&
      !Array.isArray(sourceValue) &&
      targetValue !== undefined &&
      targetValue !== null &&
      typeof targetValue === "object" &&
      !Array.isArray(targetValue)
    ) {
      result[key] = deepMerge(
        targetValue as Record<string, unknown>,
        sourceValue as Record<string, unknown>
      ) as T[keyof T]
    } else if (sourceValue !== undefined) {
      result[key] = sourceValue as T[keyof T]
    }
  }
  return result
}

export class ConfigLoader {
  static async load(path: string): Promise<SIAgentsConfig> {
    const expandedPath = expandPath(path)
    if (!existsSync(expandedPath)) {
      throw new Error(`Config file not found: ${expandedPath}`)
    }
    const content = readFileSync(expandedPath, "utf-8")
    const rawConfig = JSON.parse(content)
    const resolvedConfig = ConfigLoader.resolveEnvVars(rawConfig) as Record<string, unknown>

    // Load external policy config if specified
    if (resolvedConfig.policy && typeof resolvedConfig.policy === "object") {
      const policyConfig = resolvedConfig.policy as Record<string, unknown>
      if (policyConfig.config_path) {
        const policyPath = expandPath(policyConfig.config_path as string)
        if (existsSync(policyPath)) {
          const policyContent = readFileSync(policyPath, "utf-8")
          const externalPolicy = JSON.parse(policyContent)
          resolvedConfig.policy = { ...policyConfig, ...externalPolicy }
        }
      }
    }

    return ConfigLoader.validate(resolvedConfig)
  }

  static fromEnv(): Partial<SIAgentsConfig> {
    const config: Partial<SIAgentsConfig> = {}
    const serverPort = process.env.SI_AGENTS_PORT
    const serverHost = process.env.SI_AGENTS_HOST
    const policyEnabled = process.env.SI_AGENTS_POLICY_ENABLED
    const observeOnly = process.env.SI_AGENTS_OBSERVE_ONLY
    const taintEnabled = process.env.SI_AGENTS_TAINT_ENABLED
    const cacheDir = process.env.SI_AGENTS_CACHE_DIR
    const securityDir = process.env.SI_AGENTS_SECURITY_DIR

    if (serverPort || serverHost) {
      const serverConfig: { port?: number; host?: string } = {}
      if (serverPort) serverConfig.port = parseInt(serverPort, 10)
      if (serverHost) serverConfig.host = serverHost
      config.server = serverConfig as { port: number; host: string }
    }
    if (policyEnabled !== undefined || observeOnly !== undefined) {
      const policyConfig: { enabled?: boolean; observe_only?: boolean } = {}
      if (policyEnabled !== undefined) policyConfig.enabled = policyEnabled === "true"
      if (observeOnly !== undefined) policyConfig.observe_only = observeOnly === "true"
      config.policy = policyConfig as { enabled: boolean; observe_only: boolean }
    }
    if (taintEnabled !== undefined) {
      config.taint = {
        enabled: taintEnabled === "true",
      }
    }
    if (cacheDir) {
      config.skvm = {
        ...(config.skvm || {}),
        cache_dir: cacheDir,
      }
    }
    if (securityDir) {
      config.security = {
        security_dir: securityDir,
      }
    }
    return config
  }

  static async loadWithEnv(path: string): Promise<SIAgentsConfig> {
    const fileConfig = await ConfigLoader.load(path)
    const envConfig = ConfigLoader.fromEnv()
    const merged = deepMerge(DEFAULT_CONFIG, deepMerge(fileConfig as Record<string, unknown>, envConfig as Record<string, unknown>))
    return ConfigLoader.validate(merged)
  }

  private static resolveEnvVars(obj: unknown): unknown {
    if (typeof obj === "string") {
      return obj.replace(/\$\{(\w+)\}/g, (_, varName) => {
        const value = process.env[varName]
        if (value === undefined) {
          throw new Error(`Environment variable ${varName} is not set but referenced in config`)
        }
        return value
      })
    }
    if (Array.isArray(obj)) {
      return obj.map((item) => ConfigLoader.resolveEnvVars(item))
    }
    if (obj !== null && typeof obj === "object") {
      const result: Record<string, unknown> = {}
      for (const [key, value] of Object.entries(obj)) {
        result[key] = ConfigLoader.resolveEnvVars(value)
      }
      return result
    }
    return obj
  }

  static validate(config: unknown): SIAgentsConfig {
    const result = SIAgentsConfigSchema.safeParse(config)
    if (!result.success) {
      const errors = result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")
      throw new Error(`Config validation failed: ${errors}`)
    }
    return result.data
  }

  static getDefaultConfigPath(): string {
    const cwd = process.cwd()
    const candidates = [
      join(cwd, "si-agents.config.json"),
      join(cwd, ".si-agents", "config.json"),
      join(cwd, "config", "si-agents.config.json"),
    ]
    for (const candidate of candidates) {
      if (existsSync(candidate)) {
        return candidate
      }
    }
    return candidates[0]
  }
}
