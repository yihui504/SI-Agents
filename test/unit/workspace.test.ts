import { describe, it, expect, beforeEach, afterEach } from "bun:test"
import { existsSync, mkdirSync, rmSync, writeFileSync, readFileSync } from "node:fs"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { WorkspaceManager, withWorkspace, type WorkspaceConfig } from "../../src/optimize/workspace.ts"

describe("WorkspaceManager", () => {
  const testBaseDir = join(tmpdir(), "workspace-test-" + Date.now())

  beforeEach(() => {
    mkdirSync(testBaseDir, { recursive: true })
  })

  afterEach(() => {
    try {
      rmSync(testBaseDir, { recursive: true, force: true })
    } catch {}
  })

  describe("constructor", () => {
    it("should create with default config", () => {
      const workspace = new WorkspaceManager()
      expect(workspace).toBeDefined()
      expect(workspace.getPath()).toBeNull()
    })

    it("should accept custom config", () => {
      const config: WorkspaceConfig = {
        baseDir: testBaseDir,
        prefix: "custom-",
        autoCleanup: false,
      }
      const workspace = new WorkspaceManager(config)
      expect(workspace).toBeDefined()
    })
  })

  describe("create", () => {
    it("should create a temporary directory", async () => {
      const workspace = new WorkspaceManager({ baseDir: testBaseDir })
      const dir = await workspace.create()

      expect(dir).toBeDefined()
      expect(existsSync(dir)).toBe(true)
      expect(dir.startsWith(testBaseDir)).toBe(true)

      // Cleanup
      await workspace.cleanup()
    })

    it("should create directory with custom prefix", async () => {
      const workspace = new WorkspaceManager({
        baseDir: testBaseDir,
        prefix: "myapp-",
      })
      const dir = await workspace.create()

      expect(dir).toContain("myapp-")
      expect(existsSync(dir)).toBe(true)

      await workspace.cleanup()
    })

    it("should return existing path if workspace already created", async () => {
      const workspace = new WorkspaceManager({ baseDir: testBaseDir })
      const dir1 = await workspace.create()
      const dir2 = await workspace.create()

      expect(dir1).toBe(dir2)
      expect(existsSync(dir1)).toBe(true)

      await workspace.cleanup()
    })

    it("should create unique directory names", async () => {
      const workspace1 = new WorkspaceManager({ baseDir: testBaseDir })
      const workspace2 = new WorkspaceManager({ baseDir: testBaseDir })

      const dir1 = await workspace1.create()
      const dir2 = await workspace2.create()

      expect(dir1).not.toBe(dir2)
      expect(existsSync(dir1)).toBe(true)
      expect(existsSync(dir2)).toBe(true)

      await workspace1.cleanup()
      await workspace2.cleanup()
    })
  })

  describe("cleanup", () => {
    it("should remove the workspace directory", async () => {
      const workspace = new WorkspaceManager({ baseDir: testBaseDir })
      const dir = await workspace.create()

      expect(existsSync(dir)).toBe(true)

      await workspace.cleanup()

      expect(existsSync(dir)).toBe(false)
      expect(workspace.getPath()).toBeNull()
    })

    it("should be safe to call multiple times", async () => {
      const workspace = new WorkspaceManager({ baseDir: testBaseDir })
      await workspace.create()

      await workspace.cleanup()
      await workspace.cleanup() // Should not throw

      expect(workspace.getPath()).toBeNull()
    })

    it("should be safe to call without create", async () => {
      const workspace = new WorkspaceManager()
      // Should not throw when cleanup is called without create
      let error: Error | null = null
      try {
        await workspace.cleanup()
      } catch (e) {
        error = e as Error
      }
      expect(error).toBeNull()
    })
  })

  describe("withWorkspace", () => {
    it("should provide workspace and cleanup after use", async () => {
      const workspace = new WorkspaceManager({ baseDir: testBaseDir })
      let capturedDir: string | null = null

      const result = await workspace.withWorkspace(async (dir) => {
        capturedDir = dir
        expect(existsSync(dir)).toBe(true)

        // Write a file to verify directory works
        const testFile = join(dir, "test.txt")
        writeFileSync(testFile, "hello world")
        expect(readFileSync(testFile, "utf-8")).toBe("hello world")

        return "success"
      })

      expect(result).toBe("success")
      expect(capturedDir).not.toBeNull()
      expect(existsSync(capturedDir!)).toBe(false) // Should be cleaned up
    })

    it("should cleanup even if function throws", async () => {
      const workspace = new WorkspaceManager({ baseDir: testBaseDir })
      let capturedDir: string | null = null

      await expect(
        workspace.withWorkspace(async (dir) => {
          capturedDir = dir
          throw new Error("Test error")
        })
      ).rejects.toThrow("Test error")

      // Directory should still be cleaned up
      expect(capturedDir).not.toBeNull()
      expect(existsSync(capturedDir!)).toBe(false)
    })

    it("should support nested workspace operations", async () => {
      const workspace1 = new WorkspaceManager({ baseDir: testBaseDir })
      const workspace2 = new WorkspaceManager({ baseDir: testBaseDir })

      const result = await workspace1.withWorkspace(async (dir1) => {
        return workspace2.withWorkspace(async (dir2) => {
          expect(dir1).not.toBe(dir2)
          expect(existsSync(dir1)).toBe(true)
          expect(existsSync(dir2)).toBe(true)
          return { dir1, dir2 }
        })
      })

      // Both should be cleaned up
      expect(existsSync(result.dir1)).toBe(false)
      expect(existsSync(result.dir2)).toBe(false)
    })
  })

  describe("getPath", () => {
    it("should return null before create", () => {
      const workspace = new WorkspaceManager()
      expect(workspace.getPath()).toBeNull()
    })

    it("should return path after create", async () => {
      const workspace = new WorkspaceManager({ baseDir: testBaseDir })
      await workspace.create()
      expect(workspace.getPath()).not.toBeNull()
      await workspace.cleanup()
    })

    it("should return null after cleanup", async () => {
      const workspace = new WorkspaceManager({ baseDir: testBaseDir })
      await workspace.create()
      await workspace.cleanup()
      expect(workspace.getPath()).toBeNull()
    })
  })

  describe("isActive", () => {
    it("should return false before create", async () => {
      const workspace = new WorkspaceManager()
      expect(await workspace.isActive()).toBe(false)
    })

    it("should return true after create", async () => {
      const workspace = new WorkspaceManager({ baseDir: testBaseDir })
      await workspace.create()
      expect(await workspace.isActive()).toBe(true)
      await workspace.cleanup()
    })

    it("should return false after cleanup", async () => {
      const workspace = new WorkspaceManager({ baseDir: testBaseDir })
      await workspace.create()
      await workspace.cleanup()
      expect(await workspace.isActive()).toBe(false)
    })
  })
})

describe("withWorkspace function", () => {
  const testBaseDir = join(tmpdir(), "workspace-func-test-" + Date.now())

  beforeEach(() => {
    mkdirSync(testBaseDir, { recursive: true })
  })

  afterEach(() => {
    try {
      rmSync(testBaseDir, { recursive: true, force: true })
    } catch {}
  })

  it("should work with function only", async () => {
    let capturedDir: string | null = null

    const result = await withWorkspace(async (dir) => {
      capturedDir = dir
      expect(existsSync(dir)).toBe(true)
      return 42
    })

    expect(result).toBe(42)
    expect(capturedDir).not.toBeNull()
    expect(existsSync(capturedDir!)).toBe(false)
  })

  it("should work with config and function", async () => {
    let capturedDir: string | null = null

    const result = await withWorkspace(
      { baseDir: testBaseDir, prefix: "custom-" },
      async (dir) => {
        capturedDir = dir
        expect(dir).toContain("custom-")
        expect(existsSync(dir)).toBe(true)
        return "done"
      }
    )

    expect(result).toBe("done")
    expect(existsSync(capturedDir!)).toBe(false)
  })

  it("should cleanup on error", async () => {
    let capturedDir: string | null = null

    await expect(
      withWorkspace({ baseDir: testBaseDir }, async (dir) => {
        capturedDir = dir
        throw new Error("Test error")
      })
    ).rejects.toThrow("Test error")

    expect(existsSync(capturedDir!)).toBe(false)
  })
})
