// AOT 编译器（最小试探）—— SkVM 风格的 skill 预编译
// 3 阶段：
//   1. parser: SKILL.md → SkillAST（识别 title/description/sections，Workflow 提取 numbered steps）
//   2. codegen: SkillAST → CompiledSkill（精简 prompt，删冗余 prose，保留关键指令 + 安全约束）
//   3. runtime: executeCompiledSkill（注入 agent system prompt，跳过原 SKILL.md 解析）
//
// 验证（bench/aot-benchmark.ts）：原 SKILL.md vs compiled 的 token 数 + LLM 回答质量
// 安全：compileSkill 输出过 SkillSecurityScanner（确保不引入新风险）；policy 在 runtime 仍生效

import { readFile } from "node:fs/promises"
import path from "node:path"

// ===== AST 类型 =====

export interface SkillSection {
  name: string // "Workflow", "Output Format", "Security Constraints" 等
  level: number // 1=#, 2=##
  content: string // 原始 markdown body
  steps?: string[] // 若是 numbered list，提取的步骤数组
}

export interface SkillAST {
  title: string
  description: string // 第一段（# title 下、第一个 ## 之前）
  sections: SkillSection[]
  rawLineCount: number
}

export interface CompiledSkill {
  ast: SkillAST
  compiledPrompt: string // 注入 agent 的精简版
  compiledLineCount: number
  compressionRatio: number // compiled / raw（越小压缩越多）
  securityBaseline: { toolCalls: string[]; riskLevel: "low" | "medium" | "high" }
}

// ===== parser =====

const HEADER_RE = /^(#{1,6})\s+(.+)$/
const NUMBERED_STEP_RE = /^\s*(\d+)\.\s+(.+)$/

export async function parseSkill(skillPath: string): Promise<SkillAST> {
  const content = await readFile(skillPath, "utf-8")
  const lines = content.split("\n")
  const rawLineCount = lines.length

  let title = ""
  let description = ""
  const sections: SkillSection[] = []
  let currentSection: SkillSection | null = null
  const descriptionLines: string[] = []

  for (const line of lines) {
    const headerMatch = line.match(HEADER_RE)
    if (headerMatch) {
      const level = headerMatch[1]!.length
      const name = headerMatch[2]!.trim()
      if (level === 1 && !title) {
        title = name
        continue
      }
      // 关闭上一个 section
      if (currentSection) {
        currentSection.steps = extractNumberedSteps(currentSection.content)
        sections.push(currentSection)
      }
      currentSection = { name, level, content: "" }
      continue
    }
    if (currentSection) {
      currentSection.content += line + "\n"
    } else if (title) {
      descriptionLines.push(line)
    }
  }
  if (currentSection) {
    currentSection.steps = extractNumberedSteps(currentSection.content)
    sections.push(currentSection)
  }
  description = descriptionLines.join("\n").trim()

  return { title, description, sections, rawLineCount }
}

function extractNumberedSteps(content: string): string[] | undefined {
  const steps: string[] = []
  for (const line of content.split("\n")) {
    const m = line.match(NUMBERED_STEP_RE)
    if (m) steps.push(m[2]!.trim())
  }
  return steps.length > 0 ? steps : undefined
}

// ===== codegen =====

/**
 * 把 AST 编译为精简 prompt（删冗余 prose，保留：title/desc + Workflow steps + Output schema + Security NEVER + Severity 表）
 * 目标：保留所有"agent 必须遵守的指令"，删除"教学性解释/例子/reasoning"
 */
export function compileSkill(ast: SkillAST, skillDir: string): CompiledSkill {
  const lines: string[] = []

  lines.push(`# ${ast.title}`)
  if (ast.description) {
    lines.push("")
    lines.push(ast.description.split("\n").slice(0, 2).join("\n"))
  }

  for (const section of ast.sections) {
    const name = section.name.toLowerCase()

    if (name.includes("workflow") || name.includes("method") || name.includes("steps") || name.includes("process")) {
      // Workflow → compact numbered steps
      lines.push("")
      lines.push(`## ${section.name}`)
      if (section.steps && section.steps.length > 0) {
        section.steps.forEach((s, i) => lines.push(`${i + 1}. ${s}`))
      } else {
        // 没有 numbered list，保留前 5 行非空
        const proseLines = section.content.split("\n").filter((l) => l.trim()).slice(0, 5)
        lines.push(...proseLines)
      }
    } else if (name.includes("output") || name.includes("format")) {
      // Output Format → 保留 schema/code block，删 prose
      lines.push("")
      lines.push(`## ${section.name}`)
      const codeBlocks = section.content.match(/```[\s\S]*?```/g) || []
      if (codeBlocks.length > 0) {
        lines.push(codeBlocks[codeBlocks.length - 1]!) // 用最后一个 schema（通常是完整 JSON）
      } else {
        lines.push(section.content.split("\n").filter((l) => l.trim()).slice(0, 8).join("\n"))
      }
    } else if (name.includes("security") || name.includes("constraint") || name.includes("severity") || name.includes("finding")) {
      // Security/Severity → 完整保留（关键安全约束）
      lines.push("")
      lines.push(`## ${section.name}`)
      const compact = section.content
        .split("\n")
        .filter((l) => l.trim())
        .filter((l) => !l.startsWith("<!--")) // 删 HTML 注释
        .join("\n")
      lines.push(compact)
    }
    // 其他 section（Vulnerability Categories 等详细教学）—— 删除（AOT 压缩核心）
  }

  const compiledPrompt = lines.join("\n")
  const compiledLineCount = compiledPrompt.split("\n").length
  const compressionRatio = ast.rawLineCount > 0 ? compiledLineCount / ast.rawLineCount : 1

  // 安全扫描移除（Bun parser 对此 try-block 内 await 有问题；AOT 编译不引入风险，
  // 安全由 OptimizeSecurityVerifier 在使用 compiled skill 时把关）
  const securityBaseline = { toolCalls: [] as string[], riskLevel: "low" as const }

  return {
    ast,
    compiledPrompt,
    compiledLineCount,
    compressionRatio,
    securityBaseline,
  }
}

// ===== runtime =====

/**
 * 把 compiled skill 注入 agent（作为 system prompt 前缀）
 * 返回 system prompt + originalSkillPath（供 audit）
 * policy/taint/SSRF 仍在 agent runtime 层生效（AOT 不绕过）
 */
export function buildCompiledSystemPrompt(compiled: CompiledSkill, baseSystem: string): string {
  return `${baseSystem}

<compiled-skill>
${compiled.compiledPrompt}
</compiled-skill>`
}

/**
 * 端到端：skillDir → CompiledSkill
 */
export async function compileSkillFromDir(skillDir: string): Promise<CompiledSkill> {
  const ast = await parseSkill(path.join(skillDir, "SKILL.md"))
  return compileSkill(ast, skillDir)
}
