import { describe, it, expect, beforeEach, afterEach } from "bun:test"
import { writeFileSync, mkdirSync, rmSync } from "node:fs"
import { join } from "node:path"
import { ConfigLoader } from "../../src/config/loader.ts"

describe("ConfigLoader", () => {
  const testDir = join(import.meta.dir, "..", "fixtures")
  const testConfigPath = join(testDir, "test-config.json")

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true })
  })

  afterEach(() => {
    try { rmSync(testDir, { recursive: true }) } catch {}
  })

  describe("resolveEnvVars", () => {
    it("should replace ${ENV_VAR} with environment variable value", async () => {
      process.env.TEST_API_KEY = "test-key-123"
      writeFileSync(testConfigPath, JSON.stringify({
        server: { port: 4000, host: "127.0.0.1" },
        models: { routes: [{ name: "test", provider: "openai", api_key: "${TEST_API_KEY}", api_base: "https://api.example.com/v1", model_id: "test-model" }], default: "test" },
        skvm: { cache_dir: "~/.skvm" },
        policy: { enabled: false, observe_only: false },
        taint: { enabled: false },
        adapters: { bare_agent: { enabled: true }, openclaw: { enabled: true } },
        security: { security_dir: "~/.skvm/security" },
      }))
      const config = await ConfigLoader.load(testConfigPath)
      expect(config.models.routes[0].api_key).toBe("test-key-123")
      delete process.env.TEST_API_KEY
    })

    it("should throw error for unset environment variable", async () => {
      delete process.env.NONEXISTENT_VAR_XYZ
      writeFileSync(testConfigPath, JSON.stringify({
        server: { port: 4000, host: "127.0.0.1" },
        models: { routes: [{ name: "test", provider: "openai", api_key: "${NONEXISTENT_VAR_XYZ}", api_base: "https://api.example.com/v1", model_id: "test-model" }], default: "test" },
        skvm: { cache_dir: "~/.skvm" },
        policy: { enabled: false, observe_only: false },
        taint: { enabled: false },
        adapters: { bare_agent: { enabled: true }, openclaw: { enabled: true } },
        security: { security_dir: "~/.skvm/security" },
      }))
      expect(ConfigLoader.load(testConfigPath)).rejects.toThrow("NONEXISTENT_VAR_XYZ")
    })

    it("should not modify strings without ${} syntax", async () => {
      writeFileSync(testConfigPath, JSON.stringify({
        server: { port: 4000, host: "127.0.0.1" },
        models: { routes: [{ name: "test", provider: "openai", api_key: "plain-key", api_base: "https://api.example.com/v1", model_id: "test-model" }], default: "test" },
        skvm: { cache_dir: "~/.skvm" },
        policy: { enabled: false, observe_only: false },
        taint: { enabled: false },
        adapters: { bare_agent: { enabled: true }, openclaw: { enabled: true } },
        security: { security_dir: "~/.skvm/security" },
      }))
      const config = await ConfigLoader.load(testConfigPath)
      expect(config.models.routes[0].api_key).toBe("plain-key")
    })
  })
})
