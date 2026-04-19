import { mkdtemp, rm, exists } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { randomBytes } from "node:crypto"

/**
 * Workspace configuration options
 */
export interface WorkspaceConfig {
  /** Base directory for creating workspaces (defaults to OS temp dir) */
  baseDir?: string
  /** Prefix for workspace directory names */
  prefix?: string
  /** Whether to automatically cleanup on process exit */
  autoCleanup?: boolean
}

/**
 * Default workspace configuration
 */
const DEFAULT_CONFIG: Required<WorkspaceConfig> = {
  baseDir: tmpdir(),
  prefix: "workspace-",
  autoCleanup: true,
}

/**
 * Manages temporary workspace directories with automatic cleanup support.
 *
 * @example
 * ```typescript
 * // Basic usage with auto cleanup
 * const workspace = new WorkspaceManager();
 * const dir = await workspace.create();
 * // ... use the directory ...
 * await workspace.cleanup();
 *
 * // Using withWorkspace for automatic cleanup
 * const result = await workspace.withWorkspace(async (dir) => {
 *   // ... work in the directory ...
 *   return someResult;
 * });
 * // Directory is automatically cleaned up
 * ```
 */
export class WorkspaceManager {
  private config: Required<WorkspaceConfig>
  private workspacePath: string | null = null
  private cleanupRegistered = false

  constructor(config: WorkspaceConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
  }

  /**
   * Creates a new temporary workspace directory.
   * If a workspace already exists, returns the existing path.
   *
   * @returns Promise resolving to the workspace directory path
   * @throws Error if directory creation fails
   */
  async create(): Promise<string> {
    if (this.workspacePath && (await exists(this.workspacePath))) {
      return this.workspacePath
    }

    // Generate unique directory name with random suffix
    const randomSuffix = randomBytes(8).toString("hex")
    const dirName = `${this.config.prefix}${randomSuffix}`

    try {
      this.workspacePath = await mkdtemp(join(this.config.baseDir, dirName))

      // Register cleanup on process exit if autoCleanup is enabled
      if (this.config.autoCleanup && !this.cleanupRegistered) {
        this.registerExitHandler()
        this.cleanupRegistered = true
      }

      return this.workspacePath
    } catch (error) {
      throw new Error(
        `Failed to create workspace directory: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }

  /**
   * Cleans up the workspace directory.
   * Safe to call multiple times.
   *
   * @returns Promise that resolves when cleanup is complete
   */
  async cleanup(): Promise<void> {
    if (!this.workspacePath) {
      return
    }

    try {
      if (await exists(this.workspacePath)) {
        await rm(this.workspacePath, { recursive: true, force: true })
      }
    } catch (error) {
      // Log but don't throw - cleanup should be safe
      console.warn(
        `Warning: Failed to cleanup workspace ${this.workspacePath}: ${error instanceof Error ? error.message : String(error)}`
      )
    } finally {
      this.workspacePath = null
    }
  }

  /**
   * Executes a function with a workspace, automatically cleaning up afterwards.
   * Creates the workspace if it doesn't exist.
   *
   * @param fn - Function to execute with the workspace path
   * @returns Promise resolving to the function's return value
   * @throws Re-throws any error from the function after cleanup
   *
   * @example
   * ```typescript
   * const files = await workspace.withWorkspace(async (dir) => {
   *   await writeFile(join(dir, 'test.txt'), 'content');
   *   return readdir(dir);
   * });
   * ```
   */
  async withWorkspace<T>(fn: (dir: string) => Promise<T>): Promise<T> {
    const dir = await this.create()
    try {
      return await fn(dir)
    } finally {
      await this.cleanup()
    }
  }

  /**
   * Gets the current workspace path without creating a new one.
   *
   * @returns The workspace path or null if not created
   */
  getPath(): string | null {
    return this.workspacePath
  }

  /**
   * Checks if a workspace is currently active.
   *
   * @returns Promise resolving to true if workspace exists
   */
  async isActive(): Promise<boolean> {
    if (!this.workspacePath) {
      return false
    }
    return exists(this.workspacePath)
  }

  /**
   * Registers a cleanup handler for process exit.
   * Uses beforeexit for graceful shutdown and exit as fallback.
   */
  private registerExitHandler(): void {
    const cleanup = async () => {
      await this.cleanup()
    }

    // Handle normal exit
    process.on("beforeExit", cleanup)

    // Handle signals (SIGINT, SIGTERM, etc.)
    process.on("SIGINT", async () => {
      await cleanup()
      process.exit(130) // 128 + SIGINT(2)
    })

    process.on("SIGTERM", async () => {
      await cleanup()
      process.exit(143) // 128 + SIGTERM(15)
    })
  }
}

/**
 * Creates a workspace and executes a function with automatic cleanup.
 * Convenience function for one-off workspace usage.
 *
 * @param config - Optional workspace configuration
 * @param fn - Function to execute with the workspace path
 * @returns Promise resolving to the function's return value
 *
 * @example
 * ```typescript
 * const result = await withWorkspace({ prefix: 'myapp-' }, async (dir) => {
 *   // ... work in the directory ...
 *   return someResult;
 * });
 * ```
 */
export async function withWorkspace<T>(
  config: WorkspaceConfig,
  fn: (dir: string) => Promise<T>
): Promise<T>

export async function withWorkspace<T>(
  fn: (dir: string) => Promise<T>
): Promise<T>

export async function withWorkspace<T>(
  configOrFn: WorkspaceConfig | ((dir: string) => Promise<T>),
  fn?: (dir: string) => Promise<T>
): Promise<T> {
  if (typeof configOrFn === "function") {
    const manager = new WorkspaceManager()
    return manager.withWorkspace(configOrFn)
  }

  if (!fn) {
    throw new Error("Function argument is required when providing config")
  }

  const manager = new WorkspaceManager(configOrFn)
  return manager.withWorkspace(fn)
}
