import { mkdir, writeFile } from "node:fs/promises"
import { join } from "node:path"

/**
 * 单个测试结果
 */
export interface TestResult {
  suite: string
  name: string
  passed: boolean
  duration: number
  error?: string
}

/**
 * 测试摘要统计
 */
export interface TestSummary {
  total: number
  passed: number
  failed: number
  passRate: number
}

/**
 * 分类测试结果
 */
export interface CategorizedResults {
  security: TestResult[]
  optimization: TestResult[]
  stateManagement: TestResult[]
  policyEngine: TestResult[]
}

/**
 * 性能指标
 */
export interface PerformanceMetrics {
  totalDuration: number
  averageDuration: number
}

/**
 * 验收报告
 */
export interface AcceptanceReport {
  timestamp: string
  summary: TestSummary
  categories: CategorizedResults
  performance: PerformanceMetrics
}

/**
 * 测试类别映射
 */
const CATEGORY_KEYWORDS: Record<keyof CategorizedResults, string[]> = {
  security: ["security", "taint", "injection", "path-traversal", "command-injection", "xss", "sqli"],
  optimization: ["optimization", "optimize", "loop", "verifier", "budget", "constraint"],
  stateManagement: ["state", "run-status", "workspace", "session", "persistence"],
  policyEngine: ["policy", "rate-limit", "unary-gate", "relational", "enforcement", "nanobot"],
}

/**
 * 根据测试名称判断类别
 */
function categorizeTest(suite: string, name: string): keyof CategorizedResults {
  const fullName = `${suite} ${name}`.toLowerCase()

  for (const [category, keywords] of Object.entries(CATEGORY_KEYWORDS)) {
    for (const keyword of keywords) {
      if (fullName.includes(keyword.toLowerCase())) {
        return category as keyof CategorizedResults
      }
    }
  }

  // 默认归类到 security
  return "security"
}

/**
 * 生成验收报告
 */
export function generateReport(results: TestResult[]): AcceptanceReport {
  const timestamp = new Date().toISOString()

  // 计算摘要
  const total = results.length
  const passed = results.filter((r) => r.passed).length
  const failed = total - passed
  const passRate = total > 0 ? Math.round((passed / total) * 10000) / 100 : 0

  const summary: TestSummary = {
    total,
    passed,
    failed,
    passRate,
  }

  // 分类测试结果
  const categories: CategorizedResults = {
    security: [],
    optimization: [],
    stateManagement: [],
    policyEngine: [],
  }

  for (const result of results) {
    const category = categorizeTest(result.suite, result.name)
    categories[category].push(result)
  }

  // 计算性能指标
  const totalDuration = results.reduce((sum, r) => sum + r.duration, 0)
  const averageDuration = total > 0 ? Math.round((totalDuration / total) * 100) / 100 : 0

  const performance: PerformanceMetrics = {
    totalDuration,
    averageDuration,
  }

  return {
    timestamp,
    summary,
    categories,
    performance,
  }
}

/**
 * 生成 Markdown 格式报告
 */
function generateMarkdown(report: AcceptanceReport): string {
  const lines: string[] = []

  // 标题
  lines.push("# SI-Agents 验收报告")
  lines.push("")
  lines.push(`**生成时间**: ${report.timestamp}`)
  lines.push("")

  // 执行摘要
  lines.push("## 执行摘要")
  lines.push("")
  lines.push("| 指标 | 数值 |")
  lines.push("| --- | --- |")
  lines.push(`| 总测试数 | ${report.summary.total} |`)
  lines.push(`| 通过数 | ${report.summary.passed} |`)
  lines.push(`| 失败数 | ${report.summary.failed} |`)
  lines.push(`| 通过率 | ${report.summary.passRate}% |`)
  lines.push("")

  // 测试通过率
  lines.push("## 测试通过率")
  lines.push("")
  const passBar = "█".repeat(Math.floor(report.summary.passRate / 5))
  const failBar = "░".repeat(20 - Math.floor(report.summary.passRate / 5))
  lines.push("```")
  lines.push(`[${passBar}${failBar}] ${report.summary.passRate}%`)
  lines.push("```")
  lines.push("")

  // 各类别测试结果
  lines.push("## 各类别测试结果")
  lines.push("")

  const categoryNames: Record<keyof CategorizedResults, string> = {
    security: "安全测试",
    optimization: "优化测试",
    stateManagement: "状态管理测试",
    policyEngine: "策略引擎测试",
  }

  for (const [key, results] of Object.entries(report.categories)) {
    const categoryName = categoryNames[key as keyof CategorizedResults]
    const categoryPassed = results.filter((r) => r.passed).length
    const categoryTotal = results.length

    lines.push(`### ${categoryName}`)
    lines.push("")

    if (results.length === 0) {
      lines.push("*无测试结果*")
      lines.push("")
      continue
    }

    lines.push(`通过: ${categoryPassed}/${categoryTotal}`)
    lines.push("")
    lines.push("| 测试名称 | 状态 | 耗时 |")
    lines.push("| --- | --- | --- |")

    for (const result of results) {
      const status = result.passed ? "✓ 通过" : "✗ 失败"
      const duration = `${result.duration.toFixed(2)}ms`
      lines.push(`| ${result.name} | ${status} | ${duration} |`)
    }
    lines.push("")

    // 显示失败详情
    const failedResults = results.filter((r) => !r.passed)
    if (failedResults.length > 0) {
      lines.push("**失败详情**:")
      lines.push("")
      for (const result of failedResults) {
        lines.push(`- **${result.name}**: ${result.error || "未知错误"}`)
      }
      lines.push("")
    }
  }

  // 性能指标
  lines.push("## 性能指标")
  lines.push("")
  lines.push("| 指标 | 数值 |")
  lines.push("| --- | --- |")
  lines.push(`| 总耗时 | ${report.performance.totalDuration.toFixed(2)}ms |`)
  lines.push(`| 平均耗时 | ${report.performance.averageDuration.toFixed(2)}ms |`)
  lines.push("")

  // 验收结论
  lines.push("## 验收结论")
  lines.push("")

  if (report.summary.passRate >= 90) {
    lines.push("**状态**: 通过")
    lines.push("")
    lines.push("所有核心功能测试通过，系统满足验收标准。")
  } else if (report.summary.passRate >= 70) {
    lines.push("**状态**: 有条件通过")
    lines.push("")
    lines.push("大部分测试通过，但存在部分失败用例需要关注。")
  } else {
    lines.push("**状态**: 不通过")
    lines.push("")
    lines.push("测试通过率低于验收标准，需要修复问题后重新测试。")
  }
  lines.push("")

  // 签名
  lines.push("---")
  lines.push("")
  lines.push(`*报告由 SI-Agents 验收报告生成器自动生成*`)

  return lines.join("\n")
}

/**
 * 保存报告到指定目录
 */
export async function saveReport(report: AcceptanceReport, dir: string): Promise<void> {
  // 确保目录存在
  await mkdir(dir, { recursive: true })

  // 保存 JSON 格式报告
  const jsonPath = join(dir, "acceptance-report.json")
  await writeFile(jsonPath, JSON.stringify(report, null, 2), "utf-8")

  // 保存 Markdown 格式报告
  const mdPath = join(dir, "ACCEPTANCE_REPORT.md")
  const markdown = generateMarkdown(report)
  await writeFile(mdPath, markdown, "utf-8")
}

/**
 * Bun test 输出解析器
 */
export interface BunTestOutput {
  tests: Array<{
    name: string
    path: string
    status: "pass" | "fail" | "skip"
    duration: number
    error?: {
      message: string
    }
  }>
}

/**
 * 从 bun test JSON 输出解析测试结果
 */
export function parseBunTestOutput(output: BunTestOutput): TestResult[] {
  return output.tests.map((test) => {
    // 从路径中提取 suite 名称
    const pathParts = test.path.split(/[/\\]/)
    const suiteName = pathParts[pathParts.length - 1]?.replace(/\.test\.ts$/, "") || test.path

    return {
      suite: suiteName,
      name: test.name,
      passed: test.status === "pass",
      duration: test.duration,
      error: test.error?.message,
    }
  })
}

/**
 * 从 bun test 文本输出解析测试结果
 */
export function parseBunTestTextOutput(output: string): TestResult[] {
  const results: TestResult[] = []
  const lines = output.split("\n")

  let currentSuite = ""
  let i = 0

  while (i < lines.length) {
    const line = lines[i].trim()

    // 匹配测试文件路径
    const fileMatch = line.match(/^(.+\.test\.ts)$/)
    if (fileMatch) {
      const pathParts = fileMatch[1].split(/[/\\]/)
      currentSuite = pathParts[pathParts.length - 1]?.replace(/\.test\.ts$/, "") || fileMatch[1]
      i++
      continue
    }

    // 匹配通过的测试 (✓)
    const passMatch = line.match(/^(✓|√)\s+(.+?)\s+(\d+\.?\d*)\s*(ms|s)?$/)
    if (passMatch) {
      const name = passMatch[2]
      let duration = parseFloat(passMatch[3])
      if (passMatch[4] === "s") {
        duration = duration * 1000
      }
      results.push({
        suite: currentSuite,
        name,
        passed: true,
        duration,
      })
      i++
      continue
    }

    // 匹配失败的测试 (✗)
    const failMatch = line.match(/^(✗|×)\s+(.+?)\s+(\d+\.?\d*)\s*(ms|s)?$/)
    if (failMatch) {
      const name = failMatch[2]
      let duration = parseFloat(failMatch[3])
      if (failMatch[4] === "s") {
        duration = duration * 1000
      }

      // 尝试读取错误信息
      let error: string | undefined
      if (i + 1 < lines.length) {
        const nextLine = lines[i + 1].trim()
        if (nextLine && !nextLine.match(/^(✓|√|✗|×)/)) {
          error = nextLine
          i++
        }
      }

      results.push({
        suite: currentSuite,
        name,
        passed: false,
        duration,
        error,
      })
      i++
      continue
    }

    i++
  }

  return results
}

/**
 * 运行测试并生成报告
 */
export async function runTestsAndGenerateReport(
  testPattern: string,
  outputDir: string,
): Promise<AcceptanceReport> {
  // 使用 Bun 的 spawn API 运行测试并获取输出
  const proc = Bun.spawn(["bun", "test", testPattern, "--reporter=json"], {
    stdout: "pipe",
    stderr: "pipe",
  })

  const stdoutText = await new Response(proc.stdout).text()
  const stderrText = await new Response(proc.stderr).text()

  // 尝试解析 JSON 输出
  let results: TestResult[]

  try {
    const jsonOutput = JSON.parse(stdoutText) as BunTestOutput
    results = parseBunTestOutput(jsonOutput)
  } catch {
    // 如果 JSON 解析失败，尝试解析文本输出
    results = parseBunTestTextOutput(stdoutText + "\n" + stderrText)
  }

  // 生成报告
  const report = generateReport(results)

  // 保存报告
  await saveReport(report, outputDir)

  return report
}

/**
 * 从现有测试结果文件生成报告
 */
export async function generateReportFromResults(
  results: TestResult[],
  outputDir: string,
): Promise<AcceptanceReport> {
  const report = generateReport(results)
  await saveReport(report, outputDir)
  return report
}
