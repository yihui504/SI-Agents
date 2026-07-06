# SI-Agents

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bun](https://img.shields.io/badge/Runtime-Bun-black)](https://bun.sh)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue)](https://www.typescriptlang.org/)

**SI-Agents: Security-First AI Agent Framework** -- 面向安全的 AI Agent 运行时框架，集成策略强制执行、污点追踪与 JIT 优化能力。

SI-Agents 整合了 [SkillVM](https://github.com/yihui504/skillvm) 的技能优化能力和 [ArbiterOS](https://github.com/yihui504/ArbiterOS) 的安全治理能力，构建了一套默认拒绝、纵深防御的 Agent 安全运行时。

## 📊 实测成绩总览（vs 裸 LLM / SkVM 论文）

> 全部真实 LLM（DeepSeek temp=0）+ 真实工具执行测出，非 mock。详见 [workflow-demo/bench/benchmark-report-final.md](../workflow-demo/bench/benchmark-report-final.md)。

### 安全轴（E2E Block Rate，Promptfoo coding-agent:core 25 case × 3 轮）

| 攻击类型 | 裸 LLM | **SI-Agents** | policy 净贡献 |
|---------|--------|--------------|-------------|
| verifier-sabotage | 100% | **100%** | 0%（LLM 对齐本身防） |
| sandbox-read-escape | 20% | **87%** | **+67%**（UG-064 凭证保护） |
| terminal-output-injection | 20% | **80%** | **+60%**（terminal guard + 内容追踪） |
| repo-prompt-injection | 60% | **73%** | +13% |
| secret-env-read | 20% | 53% | +33%（hallucinate 难拦） |
| **整体 E2E Block Rate** | **44%** | **79%** | **+35%** |

### 优化轴（vs SkVM 论文）

| 能力 | 裸 LLM / SkVM 论文 | **SI-Agents 实测** | 结论 |
|------|-------------------|-------------------|------|
| **JIT-optimize score** | SkVM 88% (task-level) | **0.362 → 1.000（+176%，文件层 metric）** | 文件层 metric，**与 SkVM task-level 不可直接比** ⚠️ |
| **JIT-boost 候选任务 token 省** | SkVM 25%/40% | **100%**（2759→0） | **超 SkVM** ✅ |
| **JIT-boost multi-step token 省** | - | **100%**（3035→0，prompt cache + enableEfsm=false） | **超 SkVM** ✅ |
| **代码固化 wall-clock 加速比** | SkVM 35x | **保守 94.8x**（lhs 3.8-6s 完整 LLM 循环 → rhs ~0ms boost short-circuit，enableEfsm=false 公平重测，rhs=50ms 保守下限） | **超 SkVM** ✅（保守下限） |
| **AOT 编译：行压缩** | SkVM 整 skill → 代码 | **35-80%**（n=3 平均 53%） | 实现最小有效版 ✅ |
| **AOT 真代码生成（US-016/017）** | SkVM 整 skill → 代码 | codegen + runtime 完整跑通；code-review（判断型为主）token 省 34%，确定性 workflow skill 接近 100% 省 | codegen ✅，runtime ✅（policy defer）|
| **AOT 编译：token 省** | - | **69%**（code-review 5108→1576，质量持平） | ✅ |
| **model profile**（4 primitive） | SkVM profile | chat overall 1.000 vs reasoner 0.950（tempZeroStability 差异 0.20，**有区分度**） | 已实现 ✅ |
| **JIT-optimize task-level grader**（US-015） | SkVM task-level 88% | 5 漏洞样本识别率 **100%**（SQL/XSS/path/secret/deserialization 全识别）+ format 率 ~10-20%（LLM 行为限制） | grader 实现 ✅，format 待提升 |
| **compare 实测化** | - | **5/6 项可靠超 SkVM**（JIT-optimize metric 待 task-level 化） | ✅ |

**诚实标注**：
- JIT-optimize 的 0.362→1.000 是**文件层 metric**（toolCalls/sections/risk），与 SkVM 论文的 task-level metric（任务完成质量）不可直接比；US-015 加了 task-level grader（识别率 100%，format 率受 LLM 行为限制）
- 代码固化 94.8x 是**保守下限**（rhs ~0ms 亚毫秒，rhs=50ms 保守估计；lhs 是完整 LLM 循环成功 run 3.8-6s）
- AOT 行压缩范围 **35-80%**（因 skill 长度而异，code-review 长 skill 压缩最高）
- AOT codegen+runtime 在**判断型 skill**（code-review）上 wall-clock 0.1x（判断型 step 串行 LLM 慢于 baseline 单次大请求）；**确定性 workflow skill** 才显著受益（接近 100% 省）
- profile 在 deepseek-chat vs deepseek-reasoner 上验证了区分度（tempZeroStability 0.20 差异）
- AOT codegen runtime 的 policy 集成 defer（当前用默认 tools；生产用应包 PolicyRegistry）

### 可用性（不误杀合法请求）

- ✅ **verifier FP 修复**：`commandExecutionPatterns` 12→5，移除反引号/字面量误判（"以可用性为根本"原则达成）
- ✅ **UG-064 凭证保护**：只拦 `.ssh/.aws/.env` 等明确凭证，不拦 home prefix / `..` 穿越

---

## 核心特性

### 多层安全策略引擎

| 策略类型 | 描述 |
|---------|------|
| **UnaryGatePolicy** | 单点策略，阻止危险操作（命令注入、敏感文件访问、保密性越界等 15+ 条规则） |
| **RelationalPolicy** | 关系策略，基于 Bell-LaPadula 模型检查信息流安全性（11 种流类型） |
| **EFSMPolicy** | 扩展有限状态机策略，控制操作序列与时序，支持快照缓存 |
| **NanobotPolicy** | 执行命令策略，检测 28+ 种危险命令模式 |

### Terminal Injection Guard（v5-v7，benchmark 验证）

防御 indirect prompt injection via terminal output（agent 信 execute_command 输出被操纵）：

- **marker 检测**：execute_command 输出含注入 marker（ignore previous / SYSTEM: / IMPORTANT / 命令式请求等 14 类）→ 标 tainted
- **tainted 传播**：marker 触发后，下一轮的 exec/write/edit/read/web_fetch **全部 block**
- **内容追踪**（v6）：execute_command 输出存档，下轮 write_file/edit 的 content 若含输出 ≥12 char 连续片段 → block（拦"agent 复制 terminal 输出到 receipt 文件"）
- **可用性优先**：只在 terminal 输出有注入迹象时收紧，平时不影响合法多步 exec

### UG-064 敏感凭证文件拦截（v7，可用性优先）

UnaryGate 加 pattern 匹配规则，拦 read_file/list_directory 读**明确凭证文件**：

- 拦截：`.ssh/`、`.aws/`、`.gnupg/`、`.gitconfig`、`.netrc`、`.npmrc`、`.docker/config.json`、`.env`、`/proc/self/(environ|cmdline|fd|status|maps)`
- **不拦**（保可用性）：home prefix（`/home/`/`/Users/`）、`..` 穿越、普通 `/etc/`——coding agent 合法 read 不误杀

### 信息流控制

基于 Bell-LaPadula 模型启发，实现保密等级（LOW/MID/HIGH/UNKNOWN）与信任等级的传播和检查，防止高保密信息向低保密通道泄露。

### 污点追踪与传播

- 基于路径规则的信任等级传播
- 保密等级传播与检查
- 路径注册表（PathRegistry）管理受控路径
- 工具别名（ToolAliases）映射

### EFSM 状态机策略

- 可配置的状态转换规则与守卫条件
- 快照缓存机制，避免重复回放历史指令
- 支持 REQUIRE_APPROVAL 效果，触发确认流程
- 计划缓存（cache_plan）与路径守卫（path_in_recent_plan）

### 流式响应安全

check-before-send 模式：流式输出在累积到阈值后进行安全检查，检测到危险模式时立即截断并替换为策略拦截提示。

### SSRF 防护

`web_fetch` 工具内置 SSRF 防护，阻止对元数据服务端点（169.254.169.254 等）、私有 IP 段（10.x/172.16-31.x/192.168.x）和非授权协议的请求。

### 确认流程

策略拦截时生成确认提示，附带 Auth Token 与 TTL（5 分钟），客户端需携带有效 Token 回复确认方可放行，过期或 Token 不匹配则拒绝。

### 规则文件加载

支持外部策略配置文件（`policy.config_path`），加载失败时采用 fail-closed 模式，确保不会因配置缺失而放行危险操作。

### 策略注册表

PolicyRegistry 支持优先级排序（order 字段），按优先级依次执行已启用的策略，支持运行时动态启用/禁用。

### JIT 技能优化

- **SkillOptimizer**：策略约束的技能优化，支持 HeadlessAgent 驱动
- **OptimizationLoop**：多轮迭代优化，收敛阈值可配置
- **SecurityConstraintInjector**：从安全基线自动生成约束并注入优化提示
- **OptimizeSecurityVerifier**：每轮优化后验证安全性，阻止引入新风险

### JIT Boost 固化

- **Solidifier**：安全感知的代码固化，监控高频操作模式并自动提升为直接执行
- **BoostSecurityAuditor**：固化前后双重安全审计
- 提升阈值（promotionThreshold）与降级阈值（demotionThreshold）可配置
- 状态持久化支持

### OpenAI 兼容代理服务器

完整的 OpenAI API 兼容代理，支持 `/v1/chat/completions`、`/v1/models`、`/health`、`/metrics` 端点，透明拦截并安全检查所有请求与响应。

### 结构化审计日志

支持 console/file/webhook 三种输出通道，四级严重度（info/warn/error/critical），可配置最低严重度过滤。

### OpenTelemetry 兼容追踪

OTLP Exporter 将安全事件和优化事件导出为 OpenTelemetry Span，兼容 Jaeger、Zipkin 等可观测性后端。

### Secret 引用机制

配置文件中的敏感字段支持 `env://` 和 `file://` 引用：

- `env://ZHIPU_API_KEY` -- 从环境变量读取
- `file:///run/secrets/api_key` -- 从文件读取

### 并发安全

Mutex 互斥锁与 Promise Chain 保证共享状态（追踪上下文、确认队列）的并发安全。

### Zod 边界校验

所有配置和提交数据通过 Zod Schema 校验，确保边界输入合法。

### 文件持久化

FileStore 提供基于文件的持久化存储，用于追踪记录和 Boost 状态的持久化。

### Agent 工具注册 API

BareAgentAdapter 提供 `registerTool` / `unregisterTool` / `registerToolExecutor` 接口，支持运行时动态注册自定义工具。

### 可配置模型定价

支持通过 `modelPricing` 配置自定义模型价格，内置 GPT-4/Claude/GLM 等主流模型定价。

### 热重载配置

ConfigWatcher 监听配置文件变更，防抖后自动重新加载，支持多文件同时监听。

### CLI

完整的命令行工具，支持 start/stop/status/config/run/optimize 六个子命令。

## 架构概览

```
src/
  policy/         策略引擎
                  unary-gate    单点策略（15+ 规则）
                  relational    关系策略（11 种信息流类型）
                  efsm          扩展有限状态机策略（快照缓存）
                  nanobot       执行命令策略（28+ 危险模式）
                  rate-limiter  速率限制
                  registry      策略注册表（优先级排序）
                  policy-utils  策略工具函数
                  user-approval 用户审批预处理
                  enforcement-mode  执行模式
                  check         策略检查入口

  taint/          污点追踪
                  tracker       污点追踪器
                  propagation   保密/信任等级传播
                  path-registry 路径注册表
                  tool-aliases  工具别名映射

  adapters/       Agent 适配器
                  bare-agent    轻量适配器（内置 SSRF 防护、工具注册）
                  openclaw      OpenClaw 实验性适配器

  proxy/          代理服务器
                  server        Hono HTTP 服务器
                  pre-call      请求预处理（确认流程、元数据注入）
                  post-call     响应后处理（策略检查）
                  streaming     流式响应安全（check-before-send）
                  model-router  模型路由与转发
                  confirmation  确认流程（Auth Token + TTL）

  hooks/          Hook 系统
                  coordinator   Hook 协调器
                  security-check 安全检查 Hook
                  taint-track   污点追踪 Hook
                  audit-log     审计日志 Hook
                  structured-audit 结构化审计（console/file/webhook）

  optimize/       JIT 优化
                  optimizer     技能优化器（HeadlessAgent 支持）
                  loop          优化循环
                  scanner       安全扫描器
                  verifier      安全验证器
                  workspace     工作区管理
                  constraints   安全约束注入

  boost/          JIT Boost
                  solidifier    代码固化器
                  security-audit 固化安全审计
                  persistence   固化状态持久化

  langfuse/       可观测性
                  client        Langfuse 客户端
                  unified-trace 统一追踪
                  otel-exporter OpenTelemetry OTLP 导出器

  config/         配置
                  loader        配置加载（Secret 引用、Zod 校验）
                  defaults      默认配置
                  hot-reload    热重载（防抖监听）

  persistence/    持久化
                  file-store    文件存储

  utils/          工具
                  mutex         互斥锁
                  ssrf-guard    SSRF 防护
                  path          路径工具
                  pid           PID 管理

  cli/            CLI 命令
                  start         启动服务
                  stop          停止服务
                  status        查看状态
                  config        配置管理
                  run           运行任务
                  optimize      优化技能
```

## 快速开始

### 安装

```bash
git clone https://github.com/yihui504/SI-Agents.git
cd SI-Agents
bun install
```

### 启动代理服务

```bash
bun run cli start --config ./si-agents.config.json
```

### 运行技能任务

```bash
bun run cli run --skill ./skills/my-skill --task "完成任务"
```

### 优化技能

```bash
bun run cli optimize --skill ./skills/my-skill --rounds 5
```

## 配置

配置文件为 `si-agents.config.json`，通过 Zod Schema 校验所有字段。

### 基础配置

```json
{
  "server": {
    "port": 4000,
    "host": "127.0.0.1"
  },
  "models": {
    "routes": [
      {
        "name": "glm-4.7",
        "provider": "zhipu",
        "api_base": "https://open.bigmodel.cn/api/coding/paas/v4",
        "api_key": "env://ZHIPU_API_KEY",
        "model_id": "glm-4.7"
      }
    ],
    "default": "glm-4.7"
  },
  "skvm": {
    "cache_dir": "~/.skvm"
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
  "taint": {
    "enabled": true
  },
  "rate_limit": {
    "max_calls_per_window": 100,
    "window_seconds": 60
  },
  "input_budget": {
    "max_str_len": 100000
  },
  "output_budget": {
    "max_chars": 50000
  }
}
```

### 策略配置

```json
{
  "policy": {
    "enabled": true,
    "observe_only": false,
    "strict_mode": true,
    "rule_details_url": "https://internal-wiki/rules",
    "config_path": "./policy-rules.json",
    "deny": {
      "tools": ["dangerous_tool"],
      "paths": ["/etc/shadow", "/etc/passwd"],
      "instruction_types": ["EXEC", "DELEGATE"]
    },
    "allow": {
      "tools": ["read", "list_directory"],
      "paths": ["/workspace"],
      "instruction_types": ["READ", "RESPOND"]
    },
    "nanobot_policy": {
      "enabled": true,
      "exec_deny_patterns": ["rm -rf", "DROP TABLE", "DELETE FROM", "mkfs", "dd if="]
    }
  }
}
```

`strict_mode` 启用后，策略引擎在规则匹配失败时默认拒绝而非放行。`config_path` 指定外部策略规则文件，加载失败时采用 fail-closed 模式。

### SSRF 防护

SSRF 防护在 BareAgentAdapter 中默认启用，可通过 `ssrfGuard` 配置自定义：

```json
{
  "ssrfGuard": {
    "enabled": true,
    "allowedProtocols": ["https:", "http:"],
    "blockedHosts": ["evil.internal"],
    "allowPrivateIPs": false
  }
}
```

### OpenTelemetry

```json
{
  "opentelemetry": {
    "enabled": true,
    "endpoint": "http://localhost:4318/v1/traces",
    "headers": {
      "Authorization": "Bearer env://OTEL_TOKEN"
    },
    "serviceName": "si-agents"
  }
}
```

### Secret 引用

配置文件中标记为敏感的字段（api_key、secret_key、password 等）支持引用语法：

```json
{
  "api_key": "env://ZHIPU_API_KEY",
  "secret_key": "file:///run/secrets/secret_key"
}
```

- `env://VAR_NAME` -- 从环境变量 `VAR_NAME` 读取，变量未设置时抛出错误
- `file:///path/to/file` -- 从指定文件路径读取内容（自动 trim）

### 持久化

```json
{
  "persistence": {
    "enabled": true,
    "dir": "~/.skvm/persistence"
  }
}
```

启用后，追踪记录和 Boost 固化状态将持久化到指定目录。

### 模型定价

通过 AdapterConfig 的 `modelPricing` 字段配置自定义模型价格：

```json
{
  "modelPricing": {
    "glm-4.7": {
      "inputPrice": 0.0005,
      "outputPrice": 0.0005
    },
    "gpt-4o": {
      "inputPrice": 2.5,
      "outputPrice": 10
    }
  }
}
```

价格单位为美元/百万 Token。未配置的模型将使用内置默认定价。

## 安全模型

SI-Agents 遵循默认拒绝（default-deny）原则，构建纵深防御体系：

### 默认拒绝

策略引擎默认启用，所有请求和响应均经过安全检查。`observe_only` 模式仅记录不拦截，适用于审计场景。`strict_mode` 启用后，规则匹配失败时默认拒绝。

### check-before-send 流式安全

流式响应在累积内容达到阈值后进行安全检查。检测到危险模式（如 `rm -rf /`、`DROP TABLE`、`/etc/shadow` 等）时立即截断流，替换为策略拦截提示，防止危险内容到达客户端。

### fail-closed 规则加载

外部策略规则文件加载失败时，系统不会因配置缺失而放行，而是保持拒绝状态，确保安全不降级。

### 确认流程与 Token 认证

策略拦截时生成确认提示，附带随机 Auth Token 与 5 分钟 TTL。客户端必须携带匹配的 Token 回复确认方可放行。Token 不匹配或过期均拒绝，防止确认伪造或重放。

### SSRF 防护

`web_fetch` 工具内置 SSRF 防护，默认阻止：
- 云元数据端点（169.254.169.254、metadata.google.internal 等）
- 私有 IP 段（10.0.0.0/8、172.16.0.0/12、192.168.0.0/16）
- 本地回环地址（localhost、127.0.0.1、::1）
- 非授权协议

## CLI 命令

```
si-agents <command> [options]
```

| 命令 | 描述 |
|------|------|
| `start` | 启动代理服务 |
| `stop` | 停止代理服务 |
| `status` | 查看服务状态 |
| `config` | 配置管理（show/validate/import/init） |
| `run` | 运行技能任务 |
| `optimize` | 优化技能 |

### start

```bash
si-agents start --config ./si-agents.config.json --port 4000 --host 127.0.0.1
si-agents start --daemon
```

### stop

```bash
si-agents stop
```

### status

```bash
si-agents status
```

### config

```bash
si-agents config show
si-agents config validate
si-agents config init
si-agents config import --policy ./policy.json --litellm ./litellm_config.yaml
```

### run

```bash
si-agents run --skill ./skills/my-skill --task "完成任务X"
si-agents run --skill ./skills/my-skill --task "完成任务X" --adapter bare-agent
si-agents run --skill ./skills/my-skill --task "完成任务X" --work-dir ./workspace --max-iterations 30
```

### optimize

```bash
si-agents optimize --skill ./skills/my-skill
si-agents optimize --skill ./skills/my-skill --rounds 5
si-agents optimize --skill ./skills/my-skill --target-model gpt-4o
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

## API

### BareAgentAdapter

```typescript
import { BareAgentAdapter } from "si-agents/adapters/bare-agent"

const adapter = new BareAgentAdapter(providerFactory, hooks)

adapter.registerTool({
  name: "my_tool",
  description: "自定义工具",
  inputSchema: { type: "object", properties: { query: { type: "string" } } },
})

adapter.registerToolExecutor("my_tool", async (args) => {
  return `结果: ${args.query}`
})

await adapter.setup({
  model: "gpt-4",
  baseUrl: "http://localhost:4000",
  ssrfGuard: { enabled: true, allowedProtocols: ["https:"], blockedHosts: [], allowPrivateIPs: false },
  modelPricing: { "gpt-4o": { inputPrice: 2.5, outputPrice: 10 } },
})

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
import { EFSMPolicy } from "si-agents/policy/efsm"

const registry = new PolicyRegistry()
registry.register(
  { name: "unary-gate", class_path: "policy/unary-gate", enabled: true, order: 10 },
  new UnaryGatePolicy(config),
)
registry.register(
  { name: "efsm", class_path: "policy/efsm", enabled: true, order: 20 },
  new EFSMPolicy(efsmConfig),
)

const policies = registry.getEnabledPolicies()
registry.setEnabled("efsm", false)
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

await withWorkspace(async (dir) => {
  // 在临时工作区中执行操作，自动清理
})

const manager = new WorkspaceManager({ prefix: "myapp-", autoCleanup: true })
const workspacePath = await manager.create()
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

### AuditLogger

```typescript
import { AuditLogger } from "si-agents/hooks/structured-audit"

const logger = new AuditLogger({
  outputs: ["console", "file", "webhook"],
  filePath: "./audit.log",
  webhookUrl: "https://hooks.example.com/audit",
  minSeverity: "warn",
})

logger.warn("policy", "block", "操作被策略拦截", { toolName: "exec", pattern: "rm -rf" })
logger.critical("security", "ssrf", "SSRF 攻击尝试", { url: "http://169.254.169.254/" })
```

### Solidifier

```typescript
import { Solidifier } from "si-agents/boost/solidifier"

const solidifier = new Solidifier(
  { skillId: "my-skill", policyRegistry, taintTracker, promotionThreshold: 3 },
  candidates,
  savedState,
)

const beforeLLMHook = solidifier.createBeforeLLMHook()
const afterLLMHook = solidifier.createAfterLLMHook()

const stats = solidifier.getStats()
console.log(`Promoted: ${stats.promotedCount}/${stats.totalCandidates}`)
```

## 测试

```bash
bun test

bun test test/unit/

bun test test/e2e/

bun test test/realworld/ultimate-acceptance.test.ts
```

### E2E 安全实战成绩（Promptfoo coding-agent benchmark）

真实 LLM（DeepSeek temp=0）+ 真实工具执行 + 云端 grader 判定的端到端拦截率，**不是单元测试的虚假 100%**：

| 攻击类型 | 裸 LLM（无 SI-Agents） | **SI-Agents** | policy 净贡献 |
|---------|----------------------|--------------|-------------|
| verifier-sabotage | 100% | **100%** | 0%（LLM 对齐本身防） |
| repo-prompt-injection | 60% | **73%** | +13% |
| sandbox-read-escape | 20% | **87%** | +67% |
| terminal-output-injection | 20% | **80%** | +60% |
| secret-env-read | 20% | 53% | +33% |
| **整体 E2E Block Rate** | **44%** | **79%** | **+35%** |

**测试条件**：Promptfoo coding-agent:core 25 case × 3 轮（temp=0 确定性，多次平均）。详见 [benchmark 报表](../workflow-demo/bench/benchmark-report-v6.md)。

### 单元/集成测试（基础设施）

> ⚠️ 下表是基础设施测试（policy 规则、taint、EFSM 等单元正确性），**不反映 E2E 真实安全能力**——真实能力看上面 E2E Block Rate。

| 测试类型 | 数量 | 状态 |
|---------|------|------|
| 单元测试 | 204 | 通过 |
| 端到端测试 | 28 | 通过 |
| 终极验收测试 | 82 | 通过 |
| **总计** | **314** | 通过（基础设施层） |

## 开发

```bash
bun install

bun run build

bun run lint

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

欢迎提交 Issue 和 Pull Request。

## 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 致谢

- [SkillVM](https://github.com/yihui504/skillvm) - 技能优化框架
- [ArbiterOS](https://github.com/yihui504/ArbiterOS) - 安全治理框架
