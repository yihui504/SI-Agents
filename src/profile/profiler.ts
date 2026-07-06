// ModelProfiler —— 测 LLM 的 primitive 能力，生成 ModelProfile 供优化决策用
// 4 个维度（每个跑 N 次 sample，输出 score 0-1 + 样本数 + 原始数据）：
//   1. toolCallAccuracy: tool-call schema/参数正确率
//   2. tempZeroStability: temp=0 同 prompt 多次回复一致性
//   3. multiStepConvergence: 多步推理任务完成率
//   4. jsonOutputReliability: JSON 输出可解析率
// 运行：用真 LLM（DeepSeekProvider 等），不 mock

import type { LLMProvider, CompletionParams, LLMTool } from "../adapters/types.ts"

export interface PrimitiveScore {
  name: string
  score: number // 0-1
  sampleCount: number
  details?: string[]
}

export interface ModelProfile {
  model: string
  generatedAt: string
  primitives: PrimitiveScore[]
  overallScore: number // 4 个 primitive 平均
  durationMs: number
}

export interface ProfileConfig {
  model: string
  provider: LLMProvider
  samplesPerPrimitive?: number // 默认 5
}

const DEFAULT_SAMPLES = 5

export class ModelProfiler {
  private model: string
  private provider: LLMProvider
  private samples: number

  constructor(config: ProfileConfig) {
    this.model = config.model
    this.provider = config.provider
    this.samples = config.samplesPerPrimitive ?? DEFAULT_SAMPLES
  }

  async profile(): Promise<ModelProfile> {
    const start = Date.now()
    const primitives: PrimitiveScore[] = []

    primitives.push(await this.measureToolCallAccuracy())
    primitives.push(await this.measureTempZeroStability())
    primitives.push(await this.measureMultiStepConvergence())
    primitives.push(await this.measureJsonOutputReliability())

    const overallScore = primitives.reduce((sum, p) => sum + p.score, 0) / primitives.length

    return {
      model: this.model,
      generatedAt: new Date().toISOString(),
      primitives,
      overallScore,
      durationMs: Date.now() - start,
    }
  }

  /** 1. toolCallAccuracy: 给 LLM 一个 task + tool 定义，看是否调对 tool + 参数 */
  private async measureToolCallAccuracy(): Promise<PrimitiveScore> {
    const tool: LLMTool = {
      name: "get_weather",
      description: "Get the weather for a city",
      inputSchema: {
        type: "object",
        properties: { city: { type: "string", description: "City name" } },
        required: ["city"],
      },
    }
    const tasks = [
      { prompt: "What is the weather in Tokyo?", expectedTool: "get_weather", expectedArg: "Tokyo" },
      { prompt: "Check weather for Paris", expectedTool: "get_weather", expectedArg: "Paris" },
      { prompt: "Tell me the weather in Berlin", expectedTool: "get_weather", expectedArg: "Berlin" },
      { prompt: "Weather forecast for London please", expectedTool: "get_weather", expectedArg: "London" },
      { prompt: "How is the weather in Sydney?", expectedTool: "get_weather", expectedArg: "Sydney" },
    ]
    const details: string[] = []
    let correct = 0
    const n = Math.min(this.samples, tasks.length)

    for (let i = 0; i < n; i++) {
      const params: CompletionParams = {
        messages: [{ role: "user", content: tasks[i]!.prompt }],
        system: "Use the provided tool to answer.",
        tools: [tool],
        maxTokens: 256,
        temperature: 0,
      }
      try {
        const resp = await this.provider.complete(params)
        const tc = resp.toolCalls.find((c) => c.name === tasks[i]!.expectedTool)
        const argCity = tc?.arguments.city as string | undefined
        const ok = !!tc && typeof argCity === "string" && argCity.toLowerCase().includes(tasks[i]!.expectedArg.toLowerCase())
        if (ok) correct++
        details.push(`${tasks[i]!.prompt} → ${tc ? tc.name + "(" + JSON.stringify(tc.arguments) + ")" : "no tool"} ${ok ? "✓" : "✗"}`)
      } catch (e) {
        details.push(`${tasks[i]!.prompt} → error: ${e instanceof Error ? e.message : String(e)}`)
      }
    }

    return {
      name: "toolCallAccuracy",
      score: correct / n,
      sampleCount: n,
      details,
    }
  }

  /** 2. tempZeroStability: 同 prompt 多次跑，回复文本 hash 命中率 */
  private async measureTempZeroStability(): Promise<PrimitiveScore> {
    const prompt = "List exactly 3 fruits, one per line, no numbering."
    const responses: string[] = []
    const details: string[] = []

    for (let i = 0; i < this.samples; i++) {
      try {
        const resp = await this.provider.complete({
          messages: [{ role: "user", content: prompt }],
          maxTokens: 128,
          temperature: 0,
        })
        responses.push((resp.text || "").trim())
      } catch {
        responses.push("")
      }
    }

    // 命中率 = 出现次数最多的回复 / 总样本
    const counts = new Map<string, number>()
    for (const r of responses) counts.set(r, (counts.get(r) ?? 0) + 1)
    let maxCount = 0
    let mostCommon = ""
    for (const [r, c] of counts) {
      if (c > maxCount) {
        maxCount = c
        mostCommon = r
      }
    }
    details.push(`most common (${maxCount}/${responses.length}): ${mostCommon.slice(0, 80)}`)
    counts.forEach((c, r) => {
      if (r !== mostCommon) details.push(`variant (${c}x): ${r.slice(0, 80)}`)
    })

    return {
      name: "tempZeroStability",
      score: maxCount / responses.length,
      sampleCount: responses.length,
      details,
    }
  }

  /** 3. multiStepConvergence: 多步任务完成率（LLM 是否在一次 response 里给出完整多步方案） */
  private async measureMultiStepConvergence(): Promise<PrimitiveScore> {
    const tasks = [
      { prompt: "Describe the 3 steps to make tea (use numbered list).", expectedSteps: 3 },
      { prompt: "List 4 steps to deploy a web app (numbered).", expectedSteps: 4 },
      { prompt: "Give me 3 steps to debug a failing test (numbered).", expectedSteps: 3 },
      { prompt: "What are 5 steps to review a PR? (numbered)", expectedSteps: 5 },
      { prompt: "List 3 steps to optimize slow code (numbered).", expectedSteps: 3 },
    ]
    const details: string[] = []
    let converged = 0
    const n = Math.min(this.samples, tasks.length)

    for (let i = 0; i < n; i++) {
      try {
        const resp = await this.provider.complete({
          messages: [{ role: "user", content: tasks[i]!.prompt }],
          maxTokens: 512,
          temperature: 0,
        })
        // 数 numbered list 项（1. 2. 3. 等）
        const matches = (resp.text || "").match(/^\s*\d+\.\s+\S/gm) || []
        const ok = matches.length >= tasks[i]!.expectedSteps
        if (ok) converged++
        details.push(`${tasks[i]!.prompt.slice(0, 40)}... → ${matches.length} steps ${ok ? "✓" : `✗ (need ${tasks[i]!.expectedSteps})`}`)
      } catch (e) {
        details.push(`${tasks[i]!.prompt.slice(0, 40)}... → error`)
      }
    }

    return {
      name: "multiStepConvergence",
      score: converged / n,
      sampleCount: n,
      details,
    }
  }

  /** 4. jsonOutputReliability: 要求 JSON 输出，可解析率 */
  private async measureJsonOutputReliability(): Promise<PrimitiveScore> {
    const prompts = [
      'Return JSON: {"name": "Alice", "age": 30, "role": "admin"}',
      'Return JSON with keys: title (string), done (boolean), tags (array of strings). For a task "buy groceries".',
      'Return JSON: an object with "city" and "temperature" (number). City=Tokyo.',
      'Return JSON: {"users": [{"id": 1, "name": "Bob"}], "total": 1}',
      'Return JSON: object with "ok": true and "data": [1, 2, 3]',
    ]
    const details: string[] = []
    let parsed = 0
    const n = Math.min(this.samples, prompts.length)

    for (let i = 0; i < n; i++) {
      try {
        const resp = await this.provider.complete({
          messages: [{ role: "user", content: prompts[i]! }],
          system: "You MUST respond with ONLY valid JSON, no markdown fences, no explanation.",
          maxTokens: 256,
          temperature: 0,
        })
        const text = (resp.text || "").trim()
        // 尝试直接 parse；失败则尝试提取 ```json ... ``` 块
        let ok = false
        try {
          JSON.parse(text)
          ok = true
        } catch {
          const m = text.match(/```(?:json)?\s*([\s\S]*?)\s*```/)
          if (m) {
            try {
              JSON.parse(m[1]!)
              ok = true
            } catch {
              // not parseable
            }
          }
        }
        if (ok) parsed++
        details.push(`prompt ${i + 1}: ${ok ? "✓ parsed" : "✗ unparseable"} → ${text.slice(0, 60)}`)
      } catch (e) {
        details.push(`prompt ${i + 1}: error: ${e instanceof Error ? e.message : String(e)}`)
      }
    }

    return {
      name: "jsonOutputReliability",
      score: parsed / n,
      sampleCount: n,
      details,
    }
  }
}

/** 把 ModelProfile 转可读 markdown（供报告/调试） */
export function profileToMarkdown(p: ModelProfile): string {
  const lines: string[] = []
  lines.push(`# Model Profile: ${p.model}`)
  lines.push("")
  lines.push(`- Generated: ${p.generatedAt}`)
  lines.push(`- Duration: ${(p.durationMs / 1000).toFixed(1)}s`)
  lines.push(`- Overall: ${p.overallScore.toFixed(3)}`)
  lines.push("")
  lines.push("| Primitive | Score | Samples |")
  lines.push("|---|---|---|")
  for (const prim of p.primitives) {
    lines.push(`| ${prim.name} | ${prim.score.toFixed(2)} | ${prim.sampleCount} |`)
  }
  lines.push("")
  for (const prim of p.primitives) {
    if (prim.details && prim.details.length > 0) {
      lines.push(`## ${prim.name} details`)
      for (const d of prim.details) lines.push(`- ${d}`)
      lines.push("")
    }
  }
  return lines.join("\n")
}
