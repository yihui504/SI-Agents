import { join, basename } from "node:path"
import { stat } from "node:fs/promises"
import { existsSync } from "node:fs"
import type { OptimizeOptions } from "../types.ts"
import { ConfigLoader } from "../../config/loader.ts"
import { SkillOptimizer, type OptimizeConfig, type OptimizeResult } from "../../optimize/index.ts"
import type { SIAgentsConfig } from "../../types/config.ts"
import { expandPath } from "../../utils/path.ts"

async function validateSkillDir(skillPath: string): Promise<string> {
  const expandedPath = expandPath(skillPath)

  if (!existsSync(expandedPath)) {
    throw new Error(`技能目录不存在: ${expandedPath}`)
  }

  const s = await stat(expandedPath)
  if (!s.isDirectory()) {
    throw new Error(`路径不是目录: ${expandedPath}`)
  }

  const skillFile = join(expandedPath, "SKILL.md")
  if (!existsSync(skillFile)) {
    throw new Error(`技能文件不存在: ${skillFile}`)
  }

  return expandedPath
}

function printOptimizeResult(result: OptimizeResult): void {
  console.log("\n========== 优化结果 ==========")
  console.log(`提案 ID: ${result.proposalId}`)
  console.log(`最佳轮次: ${result.bestRound}`)
  console.log(`最终得分: ${result.finalScore.toFixed(3)}`)
  console.log(`安全审核: ${result.securityApproved ? "通过" : "未通过"}`)

  console.log("\n---------- 轮次详情 ----------")
  for (const round of result.rounds) {
    console.log(`\n轮次 ${round.round}:`)
    console.log(`  得分: ${round.score.toFixed(3)}`)
    console.log(`  安全审核: ${round.securityAuditResult}`)
    if (round.changes.length > 0) {
      console.log(`  变更:`)
      for (const change of round.changes) {
        console.log(`    - ${change}`)
      }
    }
    if (round.securityRisks.length > 0) {
      console.log(`  安全风险:`)
      for (const risk of round.securityRisks) {
        console.log(`    - ${risk}`)
      }
    }
  }
}

export async function optimizeCommand(options: OptimizeOptions): Promise<void> {
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

  let skillDir: string
  try {
    skillDir = await validateSkillDir(options.skill)
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e)
    console.error(`验证技能目录失败: ${message}`)
    process.exit(1)
  }

  const skillId = basename(skillDir)
  const targetModel = options.targetModel ?? config.models.default ?? "gpt-4o"
  const optimizerModel = targetModel
  const rounds = options.rounds ?? 3

  console.log(`技能目录: ${skillDir}`)
  console.log(`技能 ID: ${skillId}`)
  console.log(`目标模型: ${targetModel}`)
  console.log(`优化模型: ${optimizerModel}`)
  console.log(`优化轮次: ${rounds}`)
  console.log("")

  const optimizeConfig: OptimizeConfig = {
    skillId,
    skillDir,
    targetModel,
    optimizerModel,
    rounds,
    runsPerTask: 1,
  }

  console.log("开始优化技能...\n")

  const startTime = Date.now()
  const optimizer = new SkillOptimizer(optimizeConfig)
  const result = await optimizer.optimize()
  const duration = Date.now() - startTime

  printOptimizeResult(result)

  console.log(`\n优化耗时: ${(duration / 1000).toFixed(2)} 秒`)

  if (!result.securityApproved) {
    console.log("\n警告: 优化结果未通过安全审核，请手动检查变更")
    process.exit(1)
  }
}
