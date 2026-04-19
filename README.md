# SI-Agents

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bun](https://img.shields.io/badge/Runtime-Bun-black)](https://bun.sh)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue)](https://www.typescriptlang.org/)

**Security-Improved Agents** - 安全增强的 LLM Agent 运行时系统，整合 SkVM 的技能优化能力和 ArbiterOS 的安全治理能力。

## 项目背景

SI-Agents 是一个结合了 [SkillVM](https://github.com/yihui504/skillvm) 和 [ArbiterOS](https://github.com/yihui504/ArbiterOS) 优势的 Agent 增强系统：

- **来自 ArbiterOS**：完整的安全策略引擎、污点追踪、风险控制
- **来自 SkVM**：技能优化、工作区管理、性能分析
- **新增特性**：统一协调层、Langfuse 可观测性集成、多适配器支持

## 核心特性

### 🛡️ 安全策略引擎

| 策略类型 | 描述 |
|---------|------|
| **UnaryGatePolicy** | 单点策略，阻止危险操作（命令注入、敏感文件访问等） |
| **RelationalPolicy** | 关系策略，检查信息流安全性 |
| **EFSMPolicy** | 状态机策略，控制操作序列 |
| **NanobotPolicy** | 执行命令策略，检测 28+ 种危险命令模式 |

### 🔍 污点追踪

- 基于路径规则的信任等级传播
- 保密等级传播与检查
- 支持 LOW/MID/HIGH/UNKNOWN 四级分类

### ⚡ JIT 优化

- **JIT-boost**：安全感知的代码固化
- **JIT-optimize**：策略约束的技能优化
- **OptimizationLoop**：多轮迭代优化

### 📊 可观测性

- Langfuse 集成，统一的安全事件和优化事件追踪
- 完整的运行状态管理（IDLE → RUNNING → COMPLETED/ERROR）

## 安装

```bash
# 克隆仓库
git clone https://github.com/yihui504/SI-Agents.git
cd SI-Agents

# 安装依赖
bun install
```

## 快速开始

```bash
# 初始化配置
si-agents config init

# 启动代理服务
si-agents start

# 运行技能任务
si-agents run --skill ./skills/my-skill --task "完成任务"
```

## 配置

配置文件 `si-agents.config.json`：

```json
{
  "server": { "port": 4000, "host": "127.0.0.1" },
  "models": {
    "routes": [
      {
        "name": "zhipu-glm-4.7",
        "provider": "zhipu",
        "api_base": "https://open.bigmodel.cn/api/coding/paas/v4",
        "api_key": "${ZHIPU_API_KEY}",
        "model_id": "glm-4.7"
      }
    ]
  },
  "policy": {
    "enabled": true,
    "observe_only": false,
    "deny": {
      "tools": ["dangerous_tool"],
      "instruction_types": ["EXEC", "DELEGATE"]
    },
    "nanobot_policy": {
      "enabled": true,
      "exec_deny_patterns": ["rm -rf", "sudo", "chmod 777"]
    }
  },
  "taint": { "enabled": true },
  "rate_limit": {
    "max_calls_per_window": 100,
    "window_seconds": 60
  },
  "input_budget": { "max_str_len": 100000 },
  "output_budget": { "max_chars": 50000 }
}
```

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│                    SI-Agents Runtime                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │   Skill Layer   │    │  Safety Layer   │                │
│  │   (JIT-boost,   │    │  (Policy,       │                │
│  │    JIT-optimize)│    │   Taint)        │                │
│  └─────────────────┘    └─────────────────┘                │
│           │                     │                          │
│           └──────────┬──────────┘                          │
│                      ▼                                     │
│           ┌─────────────────────┐                         │
│           │   Hook Coordinator  │                         │
│           └─────────────────────┘                         │
│                      │                                     │
│           ┌─────────────────────┐                         │
│           │   Agent Adapters    │                         │
│           │ (bare-agent, ...)   │                         │
│           └─────────────────────┘                         │
└─────────────────────────────────────────────────────────────┘
```

## 策略规则

### UnaryGate 策略

| 规则 ID | 描述 |
|---------|------|
| UG-001 | 缺少元数据时阻止 |
| UG-006 | 指令类型过滤 |
| UG-010 | 参数字符串预算超限 |
| UG-020 | 执行置信度过低 |
| UG-021 | 执行可信度过低 |
| UG-030 | 高风险执行 |
| UG-031 | 需要审批 |
| UG-032 | 破坏性且不可逆 |
| UG-040 | 命中阻止标签 |
| UG-050 | 回复保密性过高 |
| UG-060 | 直接修改受保护文件 |
| UG-061 | 间接修改受保护文件 |
| UG-062 | 传播受保护文件修改指令 |
| UG-063 | 读取系统敏感文件 |
| UG-070 | 网关外部重定向 |

### Relational 策略

| 流类型 | 描述 |
|--------|------|
| read_external | 读取外部信息 |
| read_sensitive | 读取敏感信息 |
| read_state | 读取状态信息 |
| write_local | 本地写入/落盘 |
| write_shared | 共享/导出写入 |
| delegate_sink | 委托/跨会话发送 |
| comm_sink | 对外发送/可见输出 |
| voice_sink | 语音输出 |
| ui_side_effect | UI 控制副作用 |
| exec_side_effect | 执行类副作用 |
| persist_side_effect | 持久化副作用 |

## 测试

```bash
# 运行所有测试
bun test

# 运行单元测试
bun test test/unit/

# 运行端到端测试
bun test test/e2e/

# 运行终极验收测试
bun test test/realworld/ultimate-acceptance.test.ts
```

### 测试覆盖率

| 测试类型 | 数量 | 状态 |
|---------|------|------|
| 单元测试 | 204 | ✅ 通过 |
| 端到端测试 | 28 | ✅ 通过 |
| 终极验收测试 | 82 | ✅ 通过 |
| **总计** | **314** | **✅ 100% 通过** |

## API

### BareAgentAdapter

```typescript
import { BareAgentAdapter } from "si-agents/adapters/bare-agent"

const adapter = new BareAgentAdapter(providerFactory, hooks)
await adapter.setup({ model: "gpt-4", baseUrl: "http://localhost:4000" })

const result = await adapter.run({
  prompt: "完成任务",
  workDir: "/workspace",
  skillContent: skillMarkdown,
})

console.log(result.text)
console.log(result.runStatus)
```

### PolicyRegistry

```typescript
import { PolicyRegistry } from "si-agents/policy/registry"
import { UnaryGatePolicy } from "si-agents/policy/unary-gate"

const registry = new PolicyRegistry()
registry.register(
  { name: "unary-gate", class_path: "policy/unary-gate", enabled: true },
  new UnaryGatePolicy(config),
)

const policies = registry.getEnabledPolicies()
```

### TaintTracker

```typescript
import { TaintTracker } from "si-agents/taint/tracker"
import { PathRegistry } from "si-agents/taint/path-registry"

const pathRegistry = new PathRegistry()
const tracker = new TaintTracker(pathRegistry)

tracker.setBaseTaint(instruction, "read", { path: "/etc/passwd" })
tracker.propagate(instructions)

const check = tracker.checkTaintPolicy("write", args, securityType)
```

### WorkspaceManager

```typescript
import { WorkspaceManager, withWorkspace } from "si-agents/optimize/workspace"

// 使用便捷函数
await withWorkspace(async (dir) => {
  // 在临时工作区中执行操作
  // 自动清理
})

// 或使用类
const manager = new WorkspaceManager({ prefix: "myapp-", autoCleanup: true })
const workspacePath = await manager.create()
// ... 使用工作区
await manager.cleanup()
```

### OptimizationLoop

```typescript
import { OptimizationLoop, createOptimizationLoop } from "si-agents/optimize/loop"

const loop = createOptimizationLoop(optimizer, verifier, baseline, {
  maxRounds: 5,
  convergenceThreshold: 0.95,
  stopOnSecurityFailure: true,
})

const result = await loop.run()
console.log(`Best round: ${result.bestRound}`)
console.log(`Final score: ${result.finalScore}`)
console.log(`Security approved: ${result.securityApproved}`)
```

## 开发

```bash
# 安装依赖
bun install

# 构建项目
bun run build

# 类型检查
bun run typecheck

# 代码格式化
bun run format
```

## 从 ArbiterOS 迁移

```bash
si-agents config import --policy ./policy.json --litellm ./litellm_config.yaml
```

## 文档

- [SkVM 迁移报告](./docs/skvm-migration-report.md)
- [策略分析报告](./docs/policy-analysis-report.md)
- [验收报告](./test/realworld/ACCEPTANCE_REPORT.md)

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 致谢

- [SkillVM](https://github.com/yihui504/skillvm) - 技能优化框架
- [ArbiterOS](https://github.com/yihui504/ArbiterOS) - 安全治理框架
