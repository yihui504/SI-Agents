export interface OpenClawModelConfig {
  id: string
  name: string
  reasoning?: boolean
  input?: string[]
  cost?: {
    input: number
    output: number
    cacheRead?: number
    cacheWrite?: number
  }
  contextWindow?: number
  maxTokens?: number
}

export interface OpenClawProviderConfig {
  baseUrl: string
  apiKey: string
  api: string
  models: OpenClawModelConfig[]
}

export interface OpenClawConfigSnippet {
  provider: string
  baseUrl: string
  apiKey: string
  models: OpenClawModelConfig[]
}

export interface OpenClawFullConfig {
  models: {
    providers: Record<string, OpenClawProviderConfig>
  }
  agents: {
    defaults: {
      model: {
        primary: string
      }
    }
  }
}

export class OpenClawConfigGenerator {
  private proxyApiKey: string

  constructor(proxyApiKey?: string) {
    this.proxyApiKey = proxyApiKey ?? process.env.SI_AGENTS_PROXY_API_KEY ?? "si-agents-proxy"
  }

  generateConfig(params: {
    proxyUrl: string
    proxyPort: number
    modelName: string
    providerName?: string
  }): OpenClawConfigSnippet {
    const { proxyUrl, proxyPort, modelName, providerName = "si-agents" } = params

    const baseUrl = this.normalizeBaseUrl(proxyUrl, proxyPort)

    return {
      provider: providerName,
      baseUrl,
      apiKey: this.proxyApiKey,
      models: [
        {
          id: modelName,
          name: modelName,
          reasoning: false,
          input: ["text"],
          cost: {
            input: 0,
            output: 0,
            cacheRead: 0,
            cacheWrite: 0,
          },
          contextWindow: 200000,
          maxTokens: 8192,
        },
      ],
    }
  }

  generateFullConfig(params: {
    proxyUrl: string
    proxyPort: number
    models: Array<{ id: string; name: string }>
    defaultModel?: string
    providerName?: string
  }): string {
    const { proxyUrl, proxyPort, models, defaultModel, providerName = "si-agents" } = params

    const baseUrl = this.normalizeBaseUrl(proxyUrl, proxyPort)

    const modelConfigs: OpenClawModelConfig[] = models.map((m) => ({
      id: m.id,
      name: m.name,
      reasoning: false,
      input: ["text"],
      cost: {
        input: 0,
        output: 0,
        cacheRead: 0,
        cacheWrite: 0,
      },
      contextWindow: 200000,
      maxTokens: 8192,
    }))

    const config: OpenClawFullConfig = {
      models: {
        providers: {
          [providerName]: {
            baseUrl,
            apiKey: this.proxyApiKey,
            api: "openai-completions",
            models: modelConfigs,
          },
        },
      },
      agents: {
        defaults: {
          model: {
            primary: defaultModel ?? models[0]?.id ?? "default",
          },
        },
      },
    }

    return JSON.stringify(config, null, 2)
  }

  generateProviderSnippet(params: {
    proxyUrl: string
    proxyPort: number
    models: Array<{ id: string; name: string }>
    providerName?: string
  }): string {
    const { proxyUrl, proxyPort, models, providerName = "si-agents" } = params

    const baseUrl = this.normalizeBaseUrl(proxyUrl, proxyPort)

    const modelConfigs: OpenClawModelConfig[] = models.map((m) => ({
      id: m.id,
      name: m.name,
      reasoning: false,
      input: ["text"],
      cost: {
        input: 0,
        output: 0,
        cacheRead: 0,
        cacheWrite: 0,
      },
      contextWindow: 200000,
      maxTokens: 8192,
    }))

    const snippet = {
      [providerName]: {
        baseUrl,
        apiKey: this.proxyApiKey,
        api: "openai-completions",
        models: modelConfigs,
      },
    }

    return JSON.stringify(snippet, null, 2)
  }

  private normalizeBaseUrl(proxyUrl: string, proxyPort: number): string {
    let url = proxyUrl

    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      url = `http://${url}`
    }

    try {
      const parsed = new URL(url)
      if (!parsed.port) {
        parsed.port = String(proxyPort)
      }
      return parsed.origin
    } catch {
      return `http://${proxyUrl}:${proxyPort}`
    }
  }

  generateEnvVars(params: {
    proxyUrl: string
    proxyPort: number
  }): Record<string, string> {
    const baseUrl = this.normalizeBaseUrl(params.proxyUrl, params.proxyPort)

    return {
      OPENAI_API_BASE: `${baseUrl}/v1`,
      OPENAI_API_KEY: this.proxyApiKey,
      SI_AGENTS_PROXY_URL: baseUrl,
    }
  }
}

export const openClawConfigGenerator = new OpenClawConfigGenerator()
