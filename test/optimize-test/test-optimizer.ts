import { SkillOptimizer } from "../../src/optimize/optimizer.ts"
import { SkillSecurityScanner } from "../../src/optimize/scanner.ts"
import type { OptimizeConfig, SecurityConstraint } from "../../src/optimize/types.ts"
import { join } from "node:path"

async function main() {
  console.log("SkVM 性能优化功能测试")
  console.log("=".repeat(60))

  const skillDir = join(import.meta.dir, "test-skill")
  
  // Task 3.3: SecurityScanner 测试
  console.log("\n[1] SecurityScanner 测试")
  const scanner = new SkillSecurityScanner()
  const baseline = await scanner.scan(skillDir)
  
  console.log("扫描结果:")
  console.log(`  - 工具调用: ${baseline.toolCalls.length} 种`)
  console.log(`  - 路径模式: ${baseline.pathPatterns.length} 个`)
  console.log(`  - 污点流: ${baseline.taintFlows.length} 个`)
  console.log(`  - 风险等级: ${baseline.riskLevel}`)
  
  if (baseline.toolCalls.length > 0) {
    console.log(`  - 工具列表: ${baseline.toolCalls.join(", ")}`)
  }
  if (baseline.pathPatterns.length > 0) {
    console.log(`  - 路径列表: ${baseline.pathPatterns.join(", ")}`)
  }
  if (baseline.taintFlows.length > 0) {
    console.log(`  - 污点流详情:`)
    baseline.taintFlows.forEach((flow, i) => {
      console.log(`    [${i + 1}] ${flow.source} -> ${flow.sink}`)
    })
  }
  
  // Task 3.2: SkillOptimizer 测试
  console.log("\n[2] SkillOptimizer 测试")
  const securityConstraints: SecurityConstraint = {
    forbiddenTools: ["exec", "delete", "rm", "format"],
    forbiddenPaths: ["/etc/passwd", "/etc/shadow", "~/.ssh/"],
    requiredTaintRules: [],
    maxRiskLevel: "medium",
  }
  
  const config: OptimizeConfig = {
    skillId: "test-skill",
    skillDir,
    targetModel: "gpt-4o",
    optimizerModel: "gpt-4o",
    rounds: 1,
    runsPerTask: 1,
    securityConstraints,
  }
  
  const optimizer = new SkillOptimizer(config)
  
  try {
    const result = await optimizer.optimize()
    console.log("优化结果:")
    console.log(`  - 提案ID: ${result.proposalId}`)
    console.log(`  - 最佳轮次: ${result.bestRound}`)
    console.log(`  - 最终得分: ${result.finalScore.toFixed(2)}`)
    console.log(`  - 安全审批: ${result.securityApproved ? "通过" : "未通过"}`)
    console.log(`  - 轮次数: ${result.rounds.length}`)
    
    if (result.rounds.length > 0) {
      console.log(`  - 轮次详情:`)
      result.rounds.forEach((round) => {
        console.log(`    [Round ${round.round}] 得分: ${round.score.toFixed(3)}, 安全状态: ${round.securityAuditResult}`)
      })
    }
  } catch (error) {
    console.log(`优化过程出错: ${error instanceof Error ? error.message : String(error)}`)
    console.log("这是预期的，因为 opencode CLI 可能未安装")
  }

  console.log("\n" + "=".repeat(60))
  console.log("测试完成")
}

main().catch(console.error)
