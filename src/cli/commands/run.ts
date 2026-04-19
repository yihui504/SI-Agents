import { homedir } from "node:os"
import { join, basename } from "node:path"
import { readFile, readdir, stat } from "node:fs/promises"
import { existsSync } from "node:fs"
import type { RunOptions } from "../types.ts"
import { ConfigLoader } from "../../config/loader.ts"
import { PolicyRegistry } from "../../policy/registry.ts"
import { TaintTracker } from "../../taint/tracker.ts"
import { HookCoordinator } from "../../hooks/coordinator.ts"
import { BareAgentAdapter, type AdapterConfig, type AdapterRunConfig, type LLMProvider, type CompletionParams, type LLMResponse, type LLMToolResult } from "../../adapters/index.ts"
import type { SIAgentsConfig } from "../../types/config.ts"
import { expandPath } from "../../utils/path.ts"

async function loadSkill(skillPath: string): Promise<{ content: string; name: string; description: string }> {
  const expandedPath = expandPath(skillPath)

  if (!existsSync(expandedPath)) {
    throw new Error(`技能目录不存在: ${expandedPath}`)
  }

  const s = await stat(expandedPath)
  let skillDir = expandedPath
  if (!s.isDirectory()) {
    skillDir = join(expandedPath, "..")
  }

  const skillFile = join(skillDir, "SKILL.md")
  if (!existsSync(skillFile)) {
    throw new Error(`技能文件不存在: ${skillFile}`)
  }

  const content = await readFile(skillFile, "utf-8")
  const name = basename(skillDir)

  const descMatch = content.match(/^#\s+(.+)$/m)
  const description = descMatch ? descMatch[1]! : "No description"

  return { content, name, description }
}

function createOpenAIProvider(config: AdapterConfig): LLMProvider {
  const baseUrl = config.baseUrl ?? "https://api.openai.com/v1"

  return {
    name: "openai",
    complete: async (params: CompletionParams): Promise<LLMResponse> => {
      const messages = params.system
        ? [{ role: "system" as const, content: params.system }, ...params.messages]
        : params.messages

      const body: Record<string, unknown> = {
        model: config.model,
        messages,
        max_tokens: params.maxTokens ?? 4096,
        temperature: params.temperature ?? 0.7,
      }

      if (params.tools && params.tools.length > 0) {
        body.tools = params.tools.map((t) => ({
          type: "function",
          function: {
            name: t.name,
            description: t.description,
            parameters: t.inputSchema,
          },
        }))
      }

      if (params.toolChoice) {
        body.tool_choice = typeof params.toolChoice === "string"
          ? params.toolChoice
          : { type: "function", function: { name: params.toolChoice.name } }
      }

      const response = await fetch(`${baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${config.apiKey}`,
        },
        body: JSON.stringify(body),
      })

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`OpenAI API error: ${response.status} ${errorText}`)
      }

      const data = await response.json() as Record<string, unknown>
      const choice = (data.choices as Array<Record<string, unknown>>)?.[0]
      const message = choice?.message as Record<string, unknown> | undefined
      const usage = data.usage as Record<string, number> | undefined

      let text = typeof message?.content === "string" ? message.content : ""
      if ((!text || text.trim() === "") && message?.reasoning_content && typeof message.reasoning_content === "string") {
        text = message.reasoning_content
      }
      const toolCalls: Array<{ id: string; name: string; arguments: Record<string, unknown> }> = []

      if (Array.isArray(message?.tool_calls)) {
        for (const tc of message.tool_calls) {
          const func = tc.function as { name: string; arguments: string } | undefined
          if (func) {
            let args: Record<string, unknown> = {}
            try {
              args = JSON.parse(func.arguments)
            } catch {
              // ignore
            }
            toolCalls.push({
              id: tc.id as string,
              name: func.name,
              arguments: args,
            })
          }
        }
      }

      return {
        text,
        toolCalls,
        tokens: {
          input: usage?.prompt_tokens ?? 0,
          output: usage?.completion_tokens ?? 0,
        },
        durationMs: 0,
        stopReason: (choice?.finish_reason as LLMResponse["stopReason"]) ?? "end_turn",
      }
    },
    completeWithToolResults: async (
      params: CompletionParams,
      toolResults: LLMToolResult[],
      prevResponse: LLMResponse
    ): Promise<LLMResponse> => {
      const messages: Record<string, unknown>[] = params.system
        ? [{ role: "system", content: params.system }, ...params.messages]
        : [...params.messages]

      messages.push({
        role: "assistant",
        content: prevResponse.text || null,
        tool_calls: prevResponse.toolCalls.map((tc) => ({
          id: tc.id,
          type: "function",
          function: {
            name: tc.name,
            arguments: JSON.stringify(tc.arguments),
          },
        })),
      })

      for (const tr of toolResults) {
        messages.push({
          role: "tool",
          tool_call_id: tr.toolCallId,
          content: tr.content,
        })
      }

      const body: Record<string, unknown> = {
        model: config.model,
        messages,
        max_tokens: params.maxTokens ?? 4096,
        temperature: params.temperature ?? 0.7,
      }

      if (params.tools && params.tools.length > 0) {
        body.tools = params.tools.map((t) => ({
          type: "function",
          function: {
            name: t.name,
            description: t.description,
            parameters: t.inputSchema,
          },
        }))
      }

      const response = await fetch(`${baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${config.apiKey}`,
        },
        body: JSON.stringify(body),
      })

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`OpenAI API error: ${response.status} ${errorText}`)
      }

      const data = await response.json() as Record<string, unknown>
      const choice = (data.choices as Array<Record<string, unknown>>)?.[0]
      const message = choice?.message as Record<string, unknown> | undefined
      const usage = data.usage as Record<string, number> | undefined

      let text = typeof message?.content === "string" ? message.content : ""
      if ((!text || text.trim() === "") && message?.reasoning_content && typeof message.reasoning_content === "string") {
        text = message.reasoning_content
      }
      const toolCalls: Array<{ id: string; name: string; arguments: Record<string, unknown> }> = []

      if (Array.isArray(message?.tool_calls)) {
        for (const tc of message.tool_calls) {
          const func = tc.function as { name: string; arguments: string } | undefined
          if (func) {
            let args: Record<string, unknown> = {}
            try {
              args = JSON.parse(func.arguments)
            } catch {
              // ignore
            }
            toolCalls.push({
              id: tc.id as string,
              name: func.name,
              arguments: args,
            })
          }
        }
      }

      return {
        text,
        toolCalls,
        tokens: {
          input: usage?.prompt_tokens ?? 0,
          output: usage?.completion_tokens ?? 0,
        },
        durationMs: 0,
        stopReason: (choice?.finish_reason as LLMResponse["stopReason"]) ?? "end_turn",
      }
    },
  }
}

export async function runCommand(options: RunOptions): Promise<void> {
  const configPath = options.config ?? ConfigLoader.getDefaultConfigPath()
  const expandedConfigPath = expandPath(configPath)

  let config: SIAgentsConfig
  try {
    if (existsSync(expandedConfigPath)) {
      config = await ConfigLoader.loadWithEnv(expandedConfigPath)
    } else {
      config = await ConfigLoader.validate({
        server: { port: 4000, host: "127.0.0.1" },
        models: { routes: [] },
        skvm: { cache_dir: "~/.skvm" },
        policy: { enabled: false, observe_only: false },
        taint: { enabled: false },
        adapters: { bare_agent: { enabled: true }, openclaw: { enabled: true } },
        security: { security_dir: "~/.skvm/security" },
      })
    }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e)
    console.error(`加载配置失败: ${message}`)
    process.exit(1)
  }

  let skillContent: string | undefined
  let skillMeta: { name: string; description: string } | undefined

  try {
    const skill = await loadSkill(options.skill)
    skillContent = skill.content
    skillMeta = { name: skill.name, description: skill.description }
    console.log(`已加载技能: ${skill.name}`)
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e)
    console.error(`加载技能失败: ${message}`)
    process.exit(1)
  }

  const workDir = options.workDir ?? process.cwd()
  const adapterType = options.adapter ?? "bare-agent"

  console.log(`工作目录: ${workDir}`)
  console.log(`适配器: ${adapterType}`)
  console.log(`任务: ${options.task}`)
  console.log("")

  const policyRegistry = new PolicyRegistry()
  const taintTracker = new TaintTracker()

  const traceId = crypto.randomUUID()
  const logDir = join(homedir(), ".skvm", "logs")

  const hookCoordinator = new HookCoordinator({
    traceId,
    policyRegistry,
    taintTracker,
    logDir,
  })

  const model = config.models.default ?? "gpt-4o"
  const modelRoute = config.models.routes.find((r) => r.name === model)

  const adapterConfig: AdapterConfig = {
    model: modelRoute?.model_id ?? model,
    apiKey: modelRoute?.api_key ?? process.env.OPENAI_API_KEY ?? "",
    baseUrl: modelRoute?.api_base,
    maxSteps: options.maxIterations ?? 50,
    timeoutMs: 300_000,
  }

  const providerFactory = adapterType === "bare-agent"
    ? () => createOpenAIProvider(adapterConfig)
    : () => createOpenAIProvider(adapterConfig)

  const adapter = new BareAgentAdapter(providerFactory)
  adapter.setHooks(hookCoordinator.getHooks())

  await adapter.setup(adapterConfig)

  const runConfig: AdapterRunConfig = {
    prompt: options.task,
    workDir,
    skillContent,
    skillMeta,
    skillMode: "inject",
    timeoutMs: 300_000,
  }

  console.log("开始执行任务...\n")

  const startTime = Date.now()
  const result = await adapter.run(runConfig)
  const duration = Date.now() - startTime

  console.log("\n========== 执行结果 ==========")
  console.log(`状态: ${result.runStatus}`)
  console.log(`耗时: ${(duration / 1000).toFixed(2)} 秒`)
  console.log(`LLM 耗时: ${(result.llmDurationMs / 1000).toFixed(2)} 秒`)
  console.log(`Token 使用: 输入 ${result.tokens.input}, 输出 ${result.tokens.output}`)
  console.log(`预估成本: $${result.cost.toFixed(4)}`)

  if (result.statusDetail) {
    console.log(`详情: ${result.statusDetail}`)
  }

  console.log("\n---------- 输出 ----------")
  console.log(result.text)

  await adapter.teardown()
}
