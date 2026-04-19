import path from "node:path"
import { mkdir, readdir } from "node:fs/promises"
import type { LLMTool, LLMToolCall, ToolResult } from "./types.ts"

export const AGENT_TOOLS: LLMTool[] = [
  {
    name: "read_file",
    description: "Read the contents of a file at the given path relative to the working directory.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "Relative file path" } },
      required: ["path"],
    },
  },
  {
    name: "write_file",
    description: "Write content to a file at the given path relative to the working directory. Creates directories as needed.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Relative file path" },
        content: { type: "string", description: "Content to write" },
      },
      required: ["path", "content"],
    },
  },
  {
    name: "execute_command",
    description: "Execute a shell command in the working directory. Returns stdout, stderr, and exit code.",
    inputSchema: {
      type: "object",
      properties: { command: { type: "string", description: "Shell command to execute" } },
      required: ["command"],
    },
  },
  {
    name: "list_directory",
    description: "List files and directories at the given path relative to the working directory.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "Relative directory path (default: '.')" } },
    },
  },
  {
    name: "web_fetch",
    description: "Fetch a URL and return the response body. Supports GET and POST.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "URL to fetch" },
        method: { type: "string", description: "HTTP method (default: GET)" },
        headers: { type: "object", description: "Request headers" },
        body: { type: "string", description: "Request body (for POST)" },
      },
      required: ["url"],
    },
  },
]

export interface ToolExecutorOptions {
  requireReadBeforeWrite?: boolean
}

export function createToolExecutor(
  workDir: string,
  opts?: ToolExecutorOptions,
): (call: LLMToolCall) => Promise<ToolResult> {
  const readPaths = new Set<string>()

  return async (call: LLMToolCall): Promise<ToolResult> => {
    const start = performance.now()
    const args = call.arguments

    try {
      switch (call.name) {
        case "read_file": {
          return await readFile(args as { path: string }, workDir, readPaths, opts?.requireReadBeforeWrite)
        }

        case "write_file": {
          return await writeFile(args as { path: string; content: string }, workDir, readPaths, opts?.requireReadBeforeWrite)
        }

        case "execute_command": {
          return await executeCommand(args as { command: string }, workDir)
        }

        case "list_directory": {
          return await listDirectory(args as { path?: string }, workDir)
        }

        case "web_fetch": {
          return await webFetch(args as { url: string; method?: string; headers?: Record<string, string>; body?: string })
        }

        default:
          return { output: `Unknown tool: ${call.name}`, durationMs: performance.now() - start }
      }
    } catch (err) {
      return { output: `Error: ${err}`, durationMs: performance.now() - start }
    }
  }
}

export async function readFile(
  args: { path: string },
  workDir: string,
  readPaths?: Set<string>,
  trackReads?: boolean,
): Promise<ToolResult> {
  const start = performance.now()
  const filePath = path.resolve(workDir, args.path)
  const file = Bun.file(filePath)

  if (!(await file.exists())) {
    return { output: `Error: File not found: ${args.path}`, durationMs: performance.now() - start }
  }

  if (trackReads && readPaths) {
    readPaths.add(filePath)
  }

  return { output: await file.text(), durationMs: performance.now() - start }
}

export async function writeFile(
  args: { path: string; content: string },
  workDir: string,
  readPaths?: Set<string>,
  requireReadBeforeWrite?: boolean,
): Promise<ToolResult> {
  const start = performance.now()
  const filePath = path.resolve(workDir, args.path)

  if (requireReadBeforeWrite && readPaths) {
    const exists = await Bun.file(filePath).exists()
    if (exists && !readPaths.has(filePath)) {
      return {
        output: `Error: You must read_file('${args.path}') before writing to it.`,
        durationMs: performance.now() - start,
      }
    }
  }

  await mkdir(path.dirname(filePath), { recursive: true })
  await Bun.write(filePath, args.content)

  return { output: `File written: ${args.path}`, durationMs: performance.now() - start }
}

export async function listDirectory(
  args: { path?: string },
  workDir: string,
): Promise<ToolResult> {
  const start = performance.now()
  const dirPath = path.resolve(workDir, args.path ?? ".")

  try {
    const entries = await readdir(dirPath, { withFileTypes: true })
    const listing = entries
      .map((e) => `${e.isDirectory() ? "[dir]" : "[file]"} ${e.name}`)
      .join("\n")
    return { output: listing || "(empty directory)", durationMs: performance.now() - start }
  } catch (err) {
    return { output: `Error: ${err}`, durationMs: performance.now() - start }
  }
}

export async function executeCommand(
  args: { command: string },
  workDir: string,
): Promise<ToolResult> {
  const start = performance.now()
  const cmd = args.command

  if (/\b(pkill|killall)\b/.test(cmd)) {
    return {
      output: "Error: pkill/killall are not allowed. Use `kill <PID>` to stop a specific process.",
      durationMs: performance.now() - start,
    }
  }

  const TOOL_TIMEOUT_MS = 30_000
  const READ_TIMEOUT_MS = 2_000

  const proc = Bun.spawn(["sh", "-c", cmd], {
    cwd: workDir,
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, HOME: process.env.HOME },
  })

  const timeout = new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error("command timed out after 30s")), TOOL_TIMEOUT_MS),
  )

  try {
    const exitCode = await Promise.race([proc.exited, timeout])
    const readWithTimeout = <T>(p: Promise<T>, fallback: T): Promise<T> =>
      Promise.race([p, new Promise<T>((resolve) => setTimeout(() => resolve(fallback), READ_TIMEOUT_MS))])

    const stdout = await readWithTimeout(new Response(proc.stdout).text(), "")
    const stderr = await readWithTimeout(new Response(proc.stderr).text(), "")

    const output = [
      stdout ? `stdout:\n${stdout}` : "",
      stderr ? `stderr:\n${stderr}` : "",
      `exit code: ${exitCode}`,
    ].filter(Boolean).join("\n")

    return { output, exitCode, durationMs: performance.now() - start }
  } catch {
    proc.kill()
    return { output: "Error: command timed out after 30s", durationMs: performance.now() - start }
  }
}

export async function webFetch(
  args: { url: string; method?: string; headers?: Record<string, string>; body?: string },
): Promise<ToolResult> {
  const start = performance.now()
  const FETCH_TIMEOUT_MS = 30_000
  const method = args.method ?? "GET"
  const headers = args.headers ?? {}

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)

  try {
    const fetchOpts: RequestInit = { method, headers, signal: controller.signal }
    if (args.body) fetchOpts.body = args.body

    const res = await fetch(args.url, fetchOpts)
    const body = await res.text()

    return { output: `HTTP ${res.status}\n${body}`, durationMs: performance.now() - start }
  } catch (err) {
    return { output: `Error: ${err}`, durationMs: performance.now() - start }
  } finally {
    clearTimeout(timer)
  }
}
