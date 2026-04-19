import { existsSync, readFileSync } from "node:fs"
import type { ToolAliasMap } from "../types/taint.ts"
import { expandPath } from "../utils/path.ts"

export interface ArbiterOSPolicy {
  audit?: { log_allow: boolean }
  unary_gate?: {
    tool_aliases?: Record<string, string>
    security?: SecurityConfig
    risk?: RiskConfig
    tags?: TagsConfig
    rule_file?: string
    fail_closed_on_missing_instruction?: boolean
    protected_identity_llm?: { enabled: boolean }
  }
  allow?: {
    tools?: string[]
    instruction_types?: string[]
    categories?: string[]
  }
  deny?: {
    tools?: string[]
    instruction_types?: string[]
    categories?: string[]
  }
  paths?: {
    allow_prefixes?: string[]
    deny_prefixes?: string[]
  }
  input_budget?: { max_str_len: number }
  output_budget?: { max_chars: number }
  rate_limit?: {
    max_consecutive_same_tool: number
    window_seconds: number
    max_calls_per_window: number
  }
  taint?: {
    enabled: boolean
    taint_policy?: TaintPolicyConfig
  }
  efsm?: {
    enabled: boolean
    initial: string
    plan_ttl_seconds: number
    transitions: EFSMTransition[]
  }
}

export interface SecurityConfig {
  min_confidence?: string
  min_trustworthiness?: string
}

export interface RiskConfig {
  blocked_risks?: string[]
  block_approval_required?: boolean
  block_destructive?: boolean
}

export interface TagsConfig {
  blocked_tags?: string[]
}

export interface TaintPolicyConfig {
  propagate_on_read?: boolean
  propagate_on_write?: boolean
  sink_check?: boolean
}

export interface EFSMTransition {
  id: string
  from: string | string[]
  event: string | string[]
  to: string
  guard?: string
  actions?: string | string[]
  effect?: string
  priority?: number
}

export interface SIAGentsPolicyConfig {
  enabled: boolean
  observe_only: boolean
  audit?: { log_allow: boolean }
  unary_gate?: {
    tool_aliases?: Record<string, string>
    security?: SecurityConfig
    risk?: RiskConfig
    tags?: TagsConfig
    rule_file?: string
    fail_closed_on_missing_instruction?: boolean
    protected_identity_llm?: { enabled: boolean }
  }
  allow?: {
    tools?: string[]
    instruction_types?: string[]
    categories?: string[]
  }
  deny?: {
    tools?: string[]
    instruction_types?: string[]
    categories?: string[]
  }
  paths?: {
    allow_prefixes?: string[]
    deny_prefixes?: string[]
  }
  input_budget?: { max_str_len: number }
  output_budget?: { max_chars: number }
  rate_limit?: {
    max_consecutive_same_tool: number
    window_seconds: number
    max_calls_per_window: number
  }
  taint?: {
    enabled: boolean
    taint_policy?: TaintPolicyConfig
  }
  efsm?: {
    enabled: boolean
    initial: string
    plan_ttl_seconds: number
    transitions: EFSMTransition[]
  }
}

export class PolicyImporter {
  static async fromArbiterOS(path: string): Promise<SIAGentsPolicyConfig> {
    const expandedPath = expandPath(path)
    if (!existsSync(expandedPath)) {
      throw new Error(`ArbiterOS policy file not found: ${expandedPath}`)
    }
    const content = readFileSync(expandedPath, "utf-8")
    const arbiterosPolicy: ArbiterOSPolicy = JSON.parse(content)
    return PolicyImporter.convertPolicy(arbiterosPolicy)
  }

  static convertPolicy(arbiterosPolicy: ArbiterOSPolicy): SIAGentsPolicyConfig {
    const config: SIAGentsPolicyConfig = {
      enabled: true,
      observe_only: false,
    }
    if (arbiterosPolicy.audit) {
      config.audit = arbiterosPolicy.audit
    }
    if (arbiterosPolicy.unary_gate) {
      config.unary_gate = arbiterosPolicy.unary_gate
    }
    if (arbiterosPolicy.allow) {
      config.allow = arbiterosPolicy.allow
    }
    if (arbiterosPolicy.deny) {
      config.deny = arbiterosPolicy.deny
    }
    if (arbiterosPolicy.paths) {
      config.paths = arbiterosPolicy.paths
    }
    if (arbiterosPolicy.input_budget) {
      config.input_budget = arbiterosPolicy.input_budget
    }
    if (arbiterosPolicy.output_budget) {
      config.output_budget = arbiterosPolicy.output_budget
    }
    if (arbiterosPolicy.rate_limit) {
      config.rate_limit = arbiterosPolicy.rate_limit
    }
    if (arbiterosPolicy.taint) {
      config.taint = arbiterosPolicy.taint
    }
    if (arbiterosPolicy.efsm) {
      config.efsm = PolicyImporter.convertEFSM(arbiterosPolicy.efsm)
    }
    return config
  }

  static convertToolAliases(arbiterosAliases: Record<string, string>): ToolAliasMap {
    const result: ToolAliasMap = {}
    for (const [alias, canonical] of Object.entries(arbiterosAliases)) {
      result[alias.toLowerCase()] = canonical.toLowerCase()
    }
    return result
  }

  static convertEFSM(arbiterosEFSM: ArbiterOSPolicy["efsm"]): SIAGentsPolicyConfig["efsm"] {
    if (!arbiterosEFSM) {
      return {
        enabled: false,
        initial: "IDLE",
        plan_ttl_seconds: 600,
        transitions: [],
      }
    }
    return {
      enabled: arbiterosEFSM.enabled ?? false,
      initial: arbiterosEFSM.initial ?? "IDLE",
      plan_ttl_seconds: arbiterosEFSM.plan_ttl_seconds ?? 600,
      transitions: arbiterosEFSM.transitions ?? [],
    }
  }
}
