import type { ModelRoute } from "../types/config.ts"
import type { ChatCompletionRequest, ChatCompletionResponse, ToolDefinition } from "./types.ts"

export class ModelRouter {
  private routes: Map<string, ModelRoute>
  private defaultRoute: ModelRoute | null = null

  constructor(routes: ModelRoute[], defaultModel?: string) {
    this.routes = new Map()
    for (const route of routes) {
      this.routes.set(route.name, route)
      if (defaultModel && route.name === defaultModel) {
        this.defaultRoute = route
      }
    }
    if (!this.defaultRoute && routes.length > 0) {
      this.defaultRoute = routes[0]
    }
  }

  resolve(modelName: string): ModelRoute | null {
    const direct = this.routes.get(modelName)
    if (direct) return direct
    for (const [name, route] of this.routes) {
      if (route.model_id === modelName || name.toLowerCase() === modelName.toLowerCase()) {
        return route
      }
    }
    return this.defaultRoute
  }

  async forward(request: ChatCompletionRequest, route: ModelRoute): Promise<Response> {
    const url = `${route.api_base}/chat/completions`
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${route.api_key}`,
    }

    const forwardRequest: ChatCompletionRequest = {
      ...request,
      model: route.model_id,
    }

    const response = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(forwardRequest),
    })

    return response
  }

  listModels(): { id: string; name: string }[] {
    const models: { id: string; name: string }[] = []
    for (const [name, route] of this.routes) {
      models.push({ id: route.model_id, name })
    }
    return models
  }

  getRoute(name: string): ModelRoute | undefined {
    return this.routes.get(name)
  }

  getDefaultRoute(): ModelRoute | null {
    return this.defaultRoute
  }
}
