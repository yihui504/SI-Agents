import type { SIAgentsConfig } from "../types/config.ts"

export const DEFAULT_CONFIG: SIAgentsConfig = {
  server: {
    port: 4000,
    host: "127.0.0.1",
  },
  models: {
    routes: [],
  },
  skvm: {
    cache_dir: "~/.skvm",
  },
  policy: {
    enabled: true,
    observe_only: false,
  },
  taint: {
    enabled: true,
  },
  adapters: {
    bare_agent: { enabled: true },
    openclaw: { enabled: true },
  },
  security: {
    security_dir: "~/.skvm/security",
  },
}
