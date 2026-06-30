# SI-agents 策略规则分析报告

## 1. ArbiterOS 原始策略配置（policy.json）

### 1.1 配置项清单

| 配置项 | 功能 | 类型 |
|--------|------|------|
| `audit` | 审计日志配置 | `{ log_allow: boolean }` |
| `unary_gate.tool_aliases` | 工具别名映射 | `Record<string, string>` |
| `allow.tools` | 工具白名单 | `string[]` |
| `deny.tools` | 工具黑名单 | `string[]` |
| `allow.instruction_types` | 指令类型白名单 | `string[]` |
| `deny.instruction_types` | 指令类型黑名单 | `string[]` |
| `allow.categories` | 分类白名单 | `string[]` |
| `deny.categories` | 分类黑名单 | `string[]` |
| `paths.allow_prefixes` | 路径访问白名单前缀 | `string[]` |
| `paths.deny_prefixes` | 路径访问黑名单前缀 | `string[]` |
| `input_budget` | 输入预算限制 | `{ max_str_len: number }` |
| `output_budget` | 输出预算限制 | `{ max_chars: number }` |
| `rate_limit` | 速率限制 | `{ max_consecutive_same_tool, window_seconds, max_calls_per_window }` |
| `user_aggregate` | 用户聚合限制 | `{ tools, window_seconds, max_events }` |
| `schemas` | 工具参数 Schema | `Record<string, JSONSchema>` |
| `taint` | 污点追踪配置 | `{ enabled, taint_policy }` |
| `exec_composite_policy` | 复合命令策略 | `{ enabled, allow_multi_read_only, block_if_any_write, block_if_any_exec }` |
| `delete_policy` | 删除策略 | `{ enabled }` |
| `nanobot_policy` | 执行命令策略 | `{ enabled, max_repeat_external_lookups, ssrf_whitelist, exec_deny_patterns }` |
| `efsm` | 状态机配置 | `{ enabled, initial, plan_ttl_seconds, transitions[] }` |

### 1.2 工具别名映射（tool_aliases）

| 别名 | 规范名 |
|------|--------|
| write_file | write |
| edit_file | edit |
| read_file | read |
| spawn | sessions_spawn |
| patch | edit |
| terminal | exec |
| cronjob | cron |
| text_to_speech | tts |
| session_search | sessions_history |
| delegate_task | sessions_spawn |
| vision_analyze | image |
| browser_* | browser |
| process | process |

### 1.3 EFSM 状态转换规则

| ID | From | Event | To | Effect | Priority |
|----|------|-------|-----|--------|----------|
| idle_read_to_after_read | IDLE | READ | AFTER_READ | ALLOW | 100 |
| after_read_read_stay | AFTER_READ | READ | AFTER_READ | ALLOW | 95 |
| after_read_write_block | AFTER_READ | WRITE | IDLE | BLOCK | 90 |
| after_read_exec_clear | AFTER_READ | EXEC | IDLE | ALLOW | 80 |
| idle_write_ok | IDLE | WRITE | IDLE | ALLOW | 70 |
| idle_exec_ok | IDLE | EXEC | IDLE | ALLOW | 60 |

---

## 2. SI-agents 硬编码策略规则

### 2.1 UnaryGatePolicy 规则（UG-XXX）

| ID | Title | Description | Effect | Scope |
|----|-------|-------------|--------|-------|
| UG-001 | unknown tool | block unknown tool calls | BLOCK | tool |
| UG-010 | low confidence | block low confidence tool calls | BLOCK | tool |
| UG-020 | high risk | block high risk tool calls | BLOCK | tool |
| UG-021 | destructive action | block destructive actions without approval | BLOCK | tool |
| UG-030 | blocked tag | block tool calls with blocked tags | BLOCK | tool |
| UG-031 | approval required | block actions requiring approval | BLOCK | tool |
| UG-032 | blocked risk tag | block actions with blocked risk tags | BLOCK | tool |
| UG-040 | external network | block external network access | BLOCK | tool |
| UG-050 | sensitive file access | block access to sensitive files | BLOCK | tool |
| UG-060 | protected file direct modify | block direct modification of protected files | BLOCK | tool |
| UG-061 | protected file indirect modify | block indirect modification of protected files | BLOCK | tool |
| UG-062 | protected file modify propagation | block propagation of protected file modifications | BLOCK | tool |
| UG-063 | protected system sensitive file read | block read of system sensitive files | BLOCK | tool |
| UG-070 | gateway external redirect | block gateway config with external URL | BLOCK | tool |

### 2.2 RelationalPolicy 流规则

| Flow Kind | 触发条件 | 检查逻辑 |
|-----------|---------|---------|
| read_sensitive | read, read_file, memory_search, memory_get, sessions_history | sinkTrust >= sourceConf |
| read_external | web_fetch, web_search | sinkTrust >= required |
| write_shared | write, write_file, edit 到共享路径 | sinkTrust >= sourceConf |
| exec_side_effect | exec, execute_command, process | 需要审批或高信任度 |

### 2.3 EFSMPolicy 状态转换

与 ArbiterOS 相同，支持从配置加载。

---

## 3. 移植状态对照表

| ArbiterOS 配置项 | SI-agents 实现状态 | 说明 |
|------------------|-------------------|------|
| `audit` | ✅ 完整 | 结构化审计日志 AuditLogger，支持 console/file/webhook |
| `unary_gate.tool_aliases` | ✅ 完整 | tool-aliases.ts |
| `allow.tools` | ⚠️ 部分 | 通过工具注册 API 可扩展 |
| `deny.tools` | ⚠️ 部分 | 通过工具注册 API 可扩展 |
| `allow/deny.instruction_types` | ⚠️ 部分 | 通过 UnaryGate 规则实现 |
| `allow/deny.categories` | ⚠️ 部分 | 通过 UnaryGate 规则实现 |
| `paths.allow_prefixes` | ❌ 未实现 | 无路径白名单 |
| `paths.deny_prefixes` | ✅ 完整 | path-registry.ts + SSRF 防护 |
| `input_budget` | ⚠️ 部分 | UnaryGate 有 _estimateArgumentStringBudget |
| `output_budget` | ⚠️ 部分 | UnaryGate 有输出预算检查 |
| `rate_limit` | ✅ 完整 | rate-limiter.ts，滑动窗口 |
| `user_aggregate` | ❌ 未实现 | 无用户聚合限制 |
| `schemas` | ✅ 完整 | Zod Schema 边界验证 |
| `taint.enabled` | ✅ 完整 | tracker.ts |
| `taint.taint_policy` | ⚠️ 部分 | input_tools/output_tools 硬编码 |
| `exec_composite_policy` | ❌ 未实现 | 无复合命令策略 |
| `delete_policy` | ❌ 未实现 | 无删除策略 |
| `nanobot_policy` | ✅ 完整 | nanobot.ts，含 ReDoS 防护 |
| `efsm` | ✅ 完整 | efsm.ts，支持配置加载 |

---

## 4. 策略配置功能评估

### 4.1 PolicyImporter 使用情况

| 组件 | 状态 | 说明 |
|------|------|------|
| PolicyImporter 类 | ✅ 存在 | policy-import.ts |
| fromArbiterOS() 方法 | ✅ 存在 | 可加载外部策略文件 |
| convertPolicy() 方法 | ✅ 存在 | 可转换 ArbiterOS 格式 |
| 主流程调用 | ✅ 已接入 | CLI `config import` 调用 `PolicyImporter.fromArbiterOS`（cli/commands/config.ts:96）；ConfigLoader 读取并展开 `config_path`（loader.ts:81） |
| CLI 命令支持 | ✅ 已实现 | `config validate / init / import` 三个子命令（cli/commands/config.ts）；import 额外支持 LiteLLM 配置导入 |

### 4.2 配置文件支持

| 配置项 | Schema 定义 | 实际使用 |
|--------|------------|---------|
| policy.enabled | ✅ | ✅ |
| policy.observe_only | ✅ | ✅ |
| policy.config_path | ✅ | ✅ ConfigLoader 处理（loader.ts:81，expandPath 后加载规则文件） |

### 4.3 用户自定义规则可行性

**当前状态**：用户可通过 `policy.config_path` 指定外部规则文件（运行时由 ConfigLoader 加载），也可通过 CLI `config import` 从 ArbiterOS / LiteLLM 配置一次性转换导入。

**后续改进建议**：

1. **中优先级**：
   - 工具白名单/黑名单的配置化（当前通过工具注册 API 扩展）
   - 路径访问控制配置（`paths.allow_prefixes`，当前仅实现了 deny_prefixes）

2. **低优先级**：
   - 速率限制配置化（RateLimiter 已实现，配置项暴露待完善）
   - 输入/输出预算限制配置化

---

## 5. 未移植的关键功能

| 功能 | 重要性 | 风险 | 建议 |
|------|--------|------|------|
| 路径白名单 (`paths.allow_prefixes`) | 中 | 可能访问非预期路径 | 后续实现 |
| 用户聚合限制 (`user_aggregate`) | 中 | 可能被单用户滥用 | 后续实现 |
| 复合命令策略 (`exec_composite_policy`) | 中 | 可能绕过检查 | 后续实现 |
| 删除策略 (`delete_policy`) | 中 | 可能误删文件 | 后续实现 |
| 污点策略可配置化 (`taint_policy`) | 低 | 当前硬编码可工作 | 低优先级 |

---

## 6. 安全增强改进记录

以下记录了 SI-agents 在 ArbiterOS 基础策略之外新增的安全增强措施。

### 6.1 安全类 (SEC)

| 编号 | 改进项 | 说明 | 实现位置 |
|------|--------|------|---------|
| SEC-01 | 流式响应先查后发机制 | 流式 SSE 响应累积至阈值后执行策略检查，检测到危险模式立即中断并替换为拦截消息，避免危险内容直接输出 | `src/proxy/streaming.ts` |
| SEC-02 | NanobotPolicy ReDoS 防护 | 对 `exec_deny_patterns` 中的正则表达式进行静态风险检测（嵌套量词、非捕获组、超长模式等），拒绝加载可能导致回溯爆炸的模式 | `src/policy/nanobot.ts` |
| SEC-03 | 确认流程令牌认证 + TTL | 策略拦截后生成的确认请求附带 `crypto.randomUUID()` 令牌，客户端回复时必须携带匹配令牌；确认条目 5 分钟 TTL 过期自动失效 | `src/proxy/pre-call.ts`, `src/proxy/post-call.ts` |
| SEC-04 | web_fetch SSRF 防护 | 拦截对云元数据端点（169.254.169.254 等）、私有 IP 段（10.x/172.16-31.x/192.168.x）、本地回环地址的请求，支持协议白名单和自定义阻止列表 | `src/utils/ssrf-guard.ts` |
| SEC-05 | 规则文件 fail-closed 模式 | UnaryGatePolicy 加载外部规则文件失败时，`strict_mode` 下抛出异常阻止启动；非严格模式下回退到内置规则并通过审计日志告警 | `src/policy/unary-gate.ts` |

### 6.2 架构类 (ARCH)

| 编号 | 改进项 | 说明 | 实现位置 |
|------|--------|------|---------|
| ARCH-01 | Zod 边界验证 | 使用 Zod Schema 对配置文件（`SIAgentsConfigSchema`）和指令元数据（`InstructionSchema`）进行运行时边界验证，拒绝非法输入 | `src/types/config.ts`, `src/policy/check.ts` |
| ARCH-02 | 策略注册优先级排序 | PolicyRegistry 按注册 `order` 字段排序执行，默认顺序：NanobotPolicy(10) -> UnaryGatePolicy(20) -> RelationalPolicy(30) -> EFSMPolicy(40)，确保命令过滤先于权限判定 | `src/policy/check.ts`, `src/policy/registry.ts` |

### 6.3 并发安全 (CONC)

| 编号 | 改进项 | 说明 | 实现位置 |
|------|--------|------|---------|
| CONC | 并发安全 (Mutex + Promise Chain) | ProxyServer 使用 Mutex 互斥锁保护共享状态（traceContexts、pendingConfirmations）的并发访问；RateLimiter 利用 Node.js 单线程事件循环的同步原子性保证窗口内计数安全 | `src/utils/mutex.ts`, `src/proxy/server.ts`, `src/policy/rate-limiter.ts` |

### 6.4 性能优化 (PERF)

| 编号 | 改进项 | 说明 | 实现位置 |
|------|--------|------|---------|
| PERF | 污点传播 O(n^2) -> O(n) + EFSM 快照缓存 | 污点传播通过 `toolCallIdIndex` 索引将指令间查找从 O(n) 降为 O(1)，整体从 O(n^2) 优化至 O(n)；EFSMPolicy 使用 `snapshotCache` 缓存 traceId 对应的状态快照，避免重复回放历史 | `src/taint/propagation.ts`, `src/policy/efsm.ts` |

### 6.5 工程化 (ENG)

| 编号 | 改进项 | 说明 | 实现位置 |
|------|--------|------|---------|
| ENG | 结构化审计日志 + OpenTelemetry + 密钥引用 | AuditLogger 支持 console/file/webhook 三种输出，事件包含 severity/category/action/traceId 等结构化字段；集成 OpenTelemetry OTLP 导出器；配置中 `api_key`/`secret_key` 等敏感字段支持 `env://` 和 `file://` 引用，避免明文存储 | `src/hooks/structured-audit.ts`, `src/langfuse/otel-exporter.ts`, `src/config/loader.ts` |

---

## 7. 竞品对比

| 特性 | SI-agents | NeMo Guardrails | Guardrails AI | Lakera Guard |
|------|-----------|-----------------|---------------|--------------|
| **开源协议** | MIT | Apache 2.0 | Apache 2.0 | 商业产品 |
| **核心架构** | 策略链（Policy Chain）+ 污点追踪 + EFSM 状态机 | Colang 对话流 + Rails 规则 | 验证器（Validator）管道 | Prompt 注入检测 API |
| **策略表达方式** | JSON 规则文件 + Zod Schema + 代码规则 | Colang DSL + YAML 配置 | Python Validator 类 | API 调用 |
| **流式响应防护** | 先查后发，累积检测 + 中断替换 | 支持（需配置） | 支持（验证器管道） | 支持（API 模式） |
| **污点追踪** | 完整实现（传播优化 O(n)） | 无 | 无 | 无 |
| **状态机控制** | EFSM（有限状态机） | Colang 对话状态 | 无 | 无 |
| **命令注入防护** | NanobotPolicy + ReDoS 防护 | 基础关键词过滤 | 无 | 基础检测 |
| **SSRF 防护** | 内置（私有 IP + 元数据端点拦截） | 无 | 无 | 无 |
| **速率限制** | 滑动窗口 | 无内置 | 无内置 | API 级别 |
| **审计日志** | 结构化 AuditLogger（console/file/webhook） | 基础日志 | 基础日志 | 云端仪表板 |
| **可观测性** | OpenTelemetry + Langfuse | 无内置 | 无内置 | 云端仪表板 |
| **确认流程** | 令牌认证 + TTL 过期 | 用户确认块 | 无 | 无 |
| **密钥管理** | env:// + file:// 引用 | 环境变量 | 环境变量 | 托管 |
| **语言** | TypeScript (Node.js) | Python | Python | REST API |
| **适用场景** | AI Agent 安全策略引擎 | LLM 对话约束 | LLM 输出验证 | Prompt 注入防护 |

**对比总结**：

- **NeMo Guardrails** 侧重对话流控制，使用 Colang DSL 定义对话规则，适合聊天场景的边界约束，但不具备污点追踪和状态机等深层安全能力。
- **Guardrails AI** 以验证器管道为核心，擅长 LLM 输出的结构化验证（如 JSON 格式、内容质量），但缺乏运行时安全策略和命令注入防护。
- **Lakera Guard** 作为商业 SaaS 产品，提供即开即用的 Prompt 注入检测，但缺乏可定制策略引擎和细粒度访问控制。
- **SI-agents** 在策略引擎深度上领先，具备污点追踪、EFSM 状态机、SSRF 防护、令牌认证确认流程等安全特性，适合需要精细安全控制的 AI Agent 运行时场景。
