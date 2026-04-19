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
| `audit` | ⚠️ 部分 | 有 Langfuse 集成但无独立审计日志 |
| `unary_gate.tool_aliases` | ✅ 完整 | tool-aliases.ts |
| `allow.tools` | ❌ 未实现 | 无工具白名单检查 |
| `deny.tools` | ❌ 未实现 | 无工具黑名单检查 |
| `allow/deny.instruction_types` | ❌ 未实现 | 无指令类型过滤 |
| `allow/deny.categories` | ❌ 未实现 | 无分类过滤 |
| `paths.allow_prefixes` | ❌ 未实现 | 无路径白名单 |
| `paths.deny_prefixes` | ⚠️ 部分 | path-registry.ts 有硬编码规则 |
| `input_budget` | ❌ 未实现 | 无输入长度限制 |
| `output_budget` | ❌ 未实现 | 无输出长度限制 |
| `rate_limit` | ❌ 未实现 | 无速率限制 |
| `user_aggregate` | ❌ 未实现 | 无用户聚合限制 |
| `schemas` | ⚠️ 部分 | 有类型定义但无运行时验证 |
| `taint.enabled` | ✅ 完整 | tracker.ts |
| `taint.taint_policy` | ⚠️ 部分 | input_tools/output_tools 硬编码 |
| `exec_composite_policy` | ❌ 未实现 | 无复合命令策略 |
| `delete_policy` | ❌ 未实现 | 无删除策略 |
| `nanobot_policy` | ❌ 未实现 | 无执行命令策略 |
| `efsm` | ✅ 完整 | efsm.ts，支持配置加载 |

---

## 4. 策略配置功能评估

### 4.1 PolicyImporter 使用情况

| 组件 | 状态 | 说明 |
|------|------|------|
| PolicyImporter 类 | ✅ 存在 | policy-import.ts |
| fromArbiterOS() 方法 | ✅ 存在 | 可加载外部策略文件 |
| convertPolicy() 方法 | ✅ 存在 | 可转换 ArbiterOS 格式 |
| 主流程调用 | ❌ 未使用 | ConfigLoader 未调用 PolicyImporter |
| CLI 命令支持 | ❌ 无 | 无策略配置命令 |

### 4.2 配置文件支持

| 配置项 | Schema 定义 | 实际使用 |
|--------|------------|---------|
| policy.enabled | ✅ | ✅ |
| policy.observe_only | ✅ | ✅ |
| policy.config_path | ✅ | ❌ 未被 ConfigLoader 处理 |

### 4.3 用户自定义规则可行性

**当前状态**：用户无法通过配置文件自定义策略规则。

**改进建议**：

1. **高优先级**：
   - 实现 `policy.config_path` 配置支持
   - 在 ConfigLoader 中调用 PolicyImporter

2. **中优先级**：
   - 实现工具白名单/黑名单
   - 实现路径访问控制配置

3. **低优先级**：
   - 实现速率限制
   - 实现输入/输出预算限制

---

## 5. 未移植的关键功能

| 功能 | 重要性 | 风险 | 建议 |
|------|--------|------|------|
| 工具白名单/黑名单 | 高 | 可能执行未授权工具 | 立即实现 |
| 路径访问控制 | 高 | 可能访问敏感路径 | 扩展 path-registry |
| 速率限制 | 中 | 可能被滥用 | 后续实现 |
| 执行命令策略 | 高 | 可能执行危险命令 | 立即实现 |
| 复合命令策略 | 中 | 可能绕过检查 | 后续实现 |
