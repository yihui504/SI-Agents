import { existsSync, readFileSync } from "node:fs"
import type { ModelRoute } from "../types/config.ts"
import { expandPath } from "../utils/path.ts"

export interface LiteLLMConfig {
  model_list: Array<{
    model_name: string
    litellm_params: {
      model: string
      api_key: string
      api_base?: string
    }
  }>
  litellm_settings?: Record<string, unknown>
  arbiteros_config?: {
    tool_agent?: string
  }
  arbiteros_skill_trust?: {
    skills_root?: string
  }
  skill_scanner_llm?: {
    model?: string
    api_base?: string
    api_key?: string
  }
}

function extractValue(content: string, key: string): string | undefined {
  const patterns = [
    new RegExp(`^\\s*${key}\\s*:\\s*["']?([^"'\n]+)["']?`, "m"),
    new RegExp(`^\\s*${key}\\s*:\\s*([^\\n]+)`, "m"),
  ]
  for (const pattern of patterns) {
    const match = content.match(pattern)
    if (match) {
      return match[1].trim().replace(/["']/g, "")
    }
  }
  return undefined
}

function extractArray(content: string, key: string): string[] {
  const result: string[] = []
  const arrayPattern = new RegExp(`^\\s*${key}\\s*:\\s*\\[([\\s\\S]*?)\\]`, "m")
  const match = content.match(arrayPattern)
  if (match) {
    const arrayContent = match[1]
    const itemPattern = /["']([^"']+)["']/g
    let itemMatch: RegExpExecArray | null
    while ((itemMatch = itemPattern.exec(arrayContent)) !== null) {
      result.push(itemMatch[1])
    }
  }
  return result
}

function extractModelList(content: string): LiteLLMConfig["model_list"] {
  const models: LiteLLMConfig["model_list"] = []
  const modelBlockPattern = /model_list\s*:\s*\[([\s\S]*?)\n\s*\]/m
  const blockMatch = content.match(modelBlockPattern)
  if (!blockMatch) {
    return models
  }
  const blockContent = blockMatch[1]
  const modelEntryPattern = /-\s*model_name\s*:\s*["']?([^"'\n]+)["']?\s*\n([\s\S]*?)(?=-\s*model_name|\s*$)/g
  let entryMatch: RegExpExecArray | null
  while ((entryMatch = modelEntryPattern.exec(blockContent)) !== null) {
    const modelName = entryMatch[1].trim()
    const entryContent = entryMatch[2]
    const model = extractValue(entryContent, "model")
    const apiKey = extractValue(entryContent, "api_key")
    const apiBase = extractValue(entryContent, "api_base")
    if (model && apiKey) {
      models.push({
        model_name: modelName,
        litellm_params: {
          model,
          api_key: apiKey,
          ...(apiBase ? { api_base: apiBase } : {}),
        },
      })
    }
  }
  return models
}

export class LiteLLMImporter {
  static async importModelRoutes(path: string): Promise<ModelRoute[]> {
    const expandedPath = expandPath(path)
    if (!existsSync(expandedPath)) {
      throw new Error(`LiteLLM config file not found: ${expandedPath}`)
    }
    const content = readFileSync(expandedPath, "utf-8")
    const config = LiteLLMImporter.parseYAML(content)
    return LiteLLMImporter.toModelRoutes(config)
  }

  static parseYAML(content: string): LiteLLMConfig {
    const modelList = extractModelList(content)
    const litellmSettings: Record<string, unknown> = {}
    const arbiterosConfig: LiteLLMConfig["arbiteros_config"] = {}
    const arbiterosSkillTrust: LiteLLMConfig["arbiteros_skill_trust"] = {}
    const skillScannerLLM: LiteLLMConfig["skill_scanner_llm"] = {}
    const toolAgent = extractValue(content, "tool_agent")
    if (toolAgent) {
      arbiterosConfig.tool_agent = toolAgent
    }
    const skillsRoot = extractValue(content, "skills_root")
    if (skillsRoot) {
      arbiterosSkillTrust.skills_root = skillsRoot
    }
    const scannerModel = extractValue(content, "scanner_model") || extractValue(content, "skill_scanner_llm_model")
    const scannerApiBase = extractValue(content, "scanner_api_base") || extractValue(content, "skill_scanner_llm_api_base")
    const scannerApiKey = extractValue(content, "scanner_api_key") || extractValue(content, "skill_scanner_llm_api_key")
    if (scannerModel || scannerApiBase || scannerApiKey) {
      skillScannerLLM.model = scannerModel
      skillScannerLLM.api_base = scannerApiBase
      skillScannerLLM.api_key = scannerApiKey
    }
    return {
      model_list: modelList,
      litellm_settings: litellmSettings,
      ...(Object.keys(arbiterosConfig).length > 0 ? { arbiteros_config: arbiterosConfig } : {}),
      ...(Object.keys(arbiterosSkillTrust).length > 0 ? { arbiteros_skill_trust: arbiterosSkillTrust } : {}),
      ...(Object.keys(skillScannerLLM).length > 0 ? { skill_scanner_llm: skillScannerLLM } : {}),
    }
  }

  static toModelRoutes(config: LiteLLMConfig): ModelRoute[] {
    const routes: ModelRoute[] = []
    for (const model of config.model_list) {
      const params = model.litellm_params
      const provider = LiteLLMImporter.extractProvider(params.model)
      routes.push({
        name: model.model_name,
        provider,
        api_base: params.api_base || LiteLLMImporter.getDefaultApiBase(provider),
        api_key: params.api_key,
        model_id: params.model,
      })
    }
    return routes
  }

  static extractProvider(modelId: string): string {
    if (modelId.includes("/")) {
      return modelId.split("/")[0]
    }
    if (modelId.startsWith("gpt") || modelId.startsWith("o1") || modelId.startsWith("o3")) {
      return "openai"
    }
    if (modelId.startsWith("claude")) {
      return "anthropic"
    }
    if (modelId.startsWith("gemini")) {
      return "google"
    }
    if (modelId.startsWith("llama") || modelId.startsWith("mistral")) {
      return "openai"
    }
    return "openai"
  }

  static getDefaultApiBase(provider: string): string {
    const defaults: Record<string, string> = {
      openai: "https://api.openai.com/v1",
      anthropic: "https://api.anthropic.com/v1",
      google: "https://generativelanguage.googleapis.com/v1",
      azure: "https://api.openai.azure.com",
    }
    return defaults[provider] || "https://api.openai.com/v1"
  }
}
