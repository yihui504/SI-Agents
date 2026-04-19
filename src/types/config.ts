import { z } from "zod"

export const ModelRouteSchema = z.object({
  name: z.string(),
  provider: z.string(),
  api_base: z.string().url(),
  api_key: z.string(),
  model_id: z.string(),
})
export type ModelRoute = z.infer<typeof ModelRouteSchema>

export const SIAgentsConfigSchema = z.object({
  server: z.object({
    port: z.number().default(4000),
    host: z.string().default("127.0.0.1"),
  }),
  models: z.object({
    routes: z.array(ModelRouteSchema),
    default: z.string().optional(),
  }),
  skvm: z.object({
    cache_dir: z.string().default("~/.skvm"),
    data_dir: z.string().optional(),
  }),
  policy: z.object({
    config_path: z.string().optional(),
    enabled: z.boolean().default(true),
    observe_only: z.boolean().default(false),
    allow: z.object({
      tools: z.array(z.string()).optional(),
      paths: z.array(z.string()).optional(),
      instruction_types: z.array(z.string()).optional(),
    }).optional(),
    deny: z.object({
      tools: z.array(z.string()).optional(),
      paths: z.array(z.string()).optional(),
      instruction_types: z.array(z.string()).optional(),
    }).optional(),
    nanobot_policy: z.object({
      enabled: z.boolean().default(true),
      exec_deny_patterns: z.array(z.string()).default([]),
    }).optional(),
  }),
  taint: z.object({
    enabled: z.boolean().default(true),
  }),
  langfuse: z.object({
    public_key: z.string().optional(),
    secret_key: z.string().optional(),
    base_url: z.string().optional(),
  }).optional(),
  adapters: z.object({
    bare_agent: z.object({ enabled: z.boolean().default(true) }),
    openclaw: z.object({ enabled: z.boolean().default(true) }),
  }),
  security: z.object({
    security_dir: z.string().default("~/.skvm/security"),
  }),
  input_budget: z.object({
    max_str_len: z.number().optional(),
  }).optional(),
  output_budget: z.object({
    max_chars: z.number().optional(),
  }).optional(),
  rate_limit: z.object({
    max_calls_per_window: z.number().default(100),
    window_seconds: z.number().default(60),
  }).optional(),
})
export type SIAgentsConfig = z.infer<typeof SIAgentsConfigSchema>
