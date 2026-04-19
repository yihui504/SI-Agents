import { LEVEL_ORDER, type Level } from "../types/instruction.ts"
import type { PathRule } from "../types/taint.ts"

const URL_PREFIXES = ["http://", "https://", "ftp://", "ftps://"]

function normalizePath(p: string): string {
  return p.replace(/\\/g, "/")
}

function isClassifiable(p: string): boolean {
  const norm = normalizePath(p)
  if (norm.startsWith("/")) return true
  if (norm.startsWith("~/")) return true
  for (const prefix of URL_PREFIXES) {
    if (norm.startsWith(prefix)) return true
  }
  if (norm.length >= 3 && norm[1] === ":" && norm[2] === "/" && /[a-zA-Z]/.test(norm[0])) return true
  return false
}

function globMatch(path: string, pattern: string): boolean {
  const normPath = normalizePath(path)
  const normPattern = normalizePath(pattern)

  if (simpleGlob(normPath, normPattern)) return true

  const pathParts = normPath.split("/")
  const patternParts = normPattern.split("/")
  if (pathMatchRecursive(pathParts, 0, patternParts, 0)) return true

  const basename = pathParts[pathParts.length - 1] ?? ""
  if (basename && simpleGlob(basename, normPattern)) return true

  return false
}

function simpleGlob(str: string, pattern: string): boolean {
  const regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "{{GLOBSTAR}}")
    .replace(/\*/g, "[^/]*")
    .replace(/\{\{GLOBSTAR\}\}/g, ".*")
    .replace(/\?/g, "[^/]")
  try {
    return new RegExp(`^${regexStr}$`).test(str)
  } catch {
    return false
  }
}

function pathMatchRecursive(
  pathParts: string[],
  pi: number,
  patternParts: string[],
  qi: number,
): boolean {
  if (qi === patternParts.length) return pi === pathParts.length
  if (patternParts[qi] === "**") {
    if (qi + 1 === patternParts.length) return true
    for (let i = pi; i <= pathParts.length; i++) {
      if (pathMatchRecursive(pathParts, i, patternParts, qi + 1)) return true
    }
    return false
  }
  if (pi >= pathParts.length) return false
  if (simpleGlob(pathParts[pi], patternParts[qi])) {
    return pathMatchRecursive(pathParts, pi + 1, patternParts, qi + 1)
  }
  return false
}

const DEFAULT_RULES: Record<string, PathRule[]> = {
  linux: [
    { pattern: "http://**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "https://**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "ftp://**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "ftps://**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/home/*/Downloads/*", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/home/*/Downloads/**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/tmp/*", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/tmp/**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/var/tmp/*", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/var/tmp/**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/media/**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/mnt/*", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/usr/bin/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/usr/sbin/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/usr/lib/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/usr/lib/**", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/usr/share/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/usr/share/**", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/usr/local/bin/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/usr/local/lib/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/bin/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/sbin/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/lib/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/lib/**", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/lib64/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/etc/*", trustworthiness: "HIGH", confidentiality: "HIGH" },
    { pattern: "/etc/**", trustworthiness: "HIGH", confidentiality: "HIGH" },
    { pattern: "/opt/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/opt/**", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/etc/shadow", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "/etc/ssh/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "/etc/ssl/private/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.ssh/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "/home/*/.ssh/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.gnupg/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.aws/credentials", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.kube/config", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.kube/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.docker/config.json", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*.pem", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*.key", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*.p12", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*.pfx", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: ".env", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: ".env.*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*.secret", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*password*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*credentials*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*apikey*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*api_key*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*secret_key*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*private_key*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "/var/log/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "/var/log/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.config/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.config/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.local/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.local/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "/proc/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/proc/**", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/sys/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/sys/**", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/dev/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/usr/bin/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/usr/lib/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/usr/lib/**", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/usr/local/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/usr/local/**", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/bin/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/sbin/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/opt/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/opt/**", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "*.crt", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "*.cer", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: ".openclaw/openclaw.json", trustworthiness: "HIGH", confidentiality: "HIGH" },
    { pattern: ".openclaw/skills/**", trustworthiness: "HIGH", confidentiality: "HIGH" },
    { pattern: ".openclaw/workspace/**", trustworthiness: "HIGH", confidentiality: "HIGH" },
    { pattern: ".openclaw/workspace-*/**", trustworthiness: "HIGH", confidentiality: "HIGH" },
    { pattern: ".openclaw/credentials/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: ".openclaw/agents/*/sessions/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.arbiteros/*", trustworthiness: "HIGH", confidentiality: "HIGH" },
  ],
  darwin: [
    { pattern: "http://**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "https://**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "ftp://**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "ftps://**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "~/Downloads/*", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "~/Downloads/**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/Users/*/Downloads/*", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/Users/*/Downloads/**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/tmp/*", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/tmp/**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/var/tmp/*", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/var/tmp/**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/private/tmp/*", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/private/tmp/**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/Volumes/**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "/System/**", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/System/Library/**", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/Library/**", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/usr/bin/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/usr/sbin/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/usr/lib/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/usr/lib/**", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/usr/share/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/usr/share/**", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/usr/local/bin/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/usr/local/lib/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/usr/local/**", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/bin/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/sbin/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/opt/homebrew/**", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/Applications/**", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "/etc/*", trustworthiness: "HIGH", confidentiality: "HIGH" },
    { pattern: "/etc/**", trustworthiness: "HIGH", confidentiality: "HIGH" },
    { pattern: "/private/etc/*", trustworthiness: "HIGH", confidentiality: "HIGH" },
    { pattern: "/private/etc/**", trustworthiness: "HIGH", confidentiality: "HIGH" },
    { pattern: "/etc/ssh/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "/etc/ssl/private/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "/private/etc/ssh/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/Library/Keychains/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "/Library/Keychains/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.ssh/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "/Users/*/.ssh/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.gnupg/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.aws/credentials", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.kube/config", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.kube/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.docker/config.json", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*.pem", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*.key", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*.keychain", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*.keychain-db", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: ".env", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: ".env.*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*.secret", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*password*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*credentials*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*apikey*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*api_key*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*secret_key*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*private_key*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "/var/log/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "/var/log/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/Library/Application Support/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/Library/Preferences/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.config/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.config/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.local/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.local/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "/tmp/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/tmp/**", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/usr/bin/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/usr/lib/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/usr/lib/**", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/usr/local/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/usr/local/**", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/bin/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/sbin/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/System/Library/**", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/Applications/**", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "/opt/homebrew/**", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "*.crt", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "*.cer", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: ".openclaw/openclaw.json", trustworthiness: "HIGH", confidentiality: "HIGH" },
    { pattern: ".openclaw/skills/**", trustworthiness: "HIGH", confidentiality: "HIGH" },
    { pattern: ".openclaw/workspace/**", trustworthiness: "HIGH", confidentiality: "HIGH" },
    { pattern: ".openclaw/workspace-*/**", trustworthiness: "HIGH", confidentiality: "HIGH" },
    { pattern: ".openclaw/credentials/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: ".openclaw/agents/*/sessions/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "~/.arbiteros/*", trustworthiness: "HIGH", confidentiality: "HIGH" },
  ],
  windows: [
    { pattern: "http://**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "https://**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "ftp://**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "ftps://**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "C:/Users/*/Downloads/*", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "C:/Users/*/Downloads/**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "C:/Temp/*", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "C:/Temp/**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "C:/Windows/Temp/*", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "C:/Users/*/AppData/Local/Temp/*", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "C:/Users/*/AppData/Local/Temp/**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "D:/**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "E:/**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "F:/**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "G:/**", trustworthiness: "LOW", confidentiality: "UNKNOWN" },
    { pattern: "C:/Windows/System32/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "C:/Windows/System32/**", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "C:/Windows/SysWOW64/*", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "C:/Windows/SysWOW64/**", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "C:/Windows/**", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "C:/Program Files/**", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "C:/Program Files (x86)/**", trustworthiness: "HIGH", confidentiality: "UNKNOWN" },
    { pattern: "C:/Windows/System32/config/SAM", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "C:/Windows/System32/config/SYSTEM", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "C:/Windows/System32/config/SECURITY", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "C:/Windows/System32/config/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "C:/Windows/System32/config/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "C:/Users/*/.ssh/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "C:/Users/*/.gnupg/*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "C:/Users/*/.aws/credentials", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "C:/Users/*/.kube/config", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "C:/Users/*/.kube/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "C:/Users/*/.docker/config.json", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "C:/Users/*/AppData/Roaming/Microsoft/Protect/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "C:/Users/*/AppData/Roaming/Microsoft/Credentials/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "C:/Users/*/AppData/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*.pem", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*.key", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*.p12", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*.pfx", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: ".env", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: ".env.*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*.secret", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*password*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*credentials*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*apikey*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*api_key*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*secret_key*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "*private_key*", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "C:/Windows/System32/winevt/Logs/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "C:/Temp/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "C:/Temp/**", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "C:/Windows/Temp/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "C:/Windows/System32/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "C:/Windows/SysWOW64/*", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "C:/Program Files/**", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "C:/Program Files (x86)/**", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "C:/Users/Public/**", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "*.crt", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: "*.cer", trustworthiness: "UNKNOWN", confidentiality: "LOW" },
    { pattern: ".openclaw/openclaw.json", trustworthiness: "HIGH", confidentiality: "HIGH" },
    { pattern: ".openclaw/skills/**", trustworthiness: "HIGH", confidentiality: "HIGH" },
    { pattern: ".openclaw/workspace/**", trustworthiness: "HIGH", confidentiality: "HIGH" },
    { pattern: ".openclaw/workspace-*/**", trustworthiness: "HIGH", confidentiality: "HIGH" },
    { pattern: ".openclaw/credentials/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: ".openclaw/agents/*/sessions/**", trustworthiness: "UNKNOWN", confidentiality: "HIGH" },
    { pattern: "C:/Users/*/.arbiteros/**", trustworthiness: "HIGH", confidentiality: "HIGH" },
  ],
}

type Platform = "linux" | "darwin" | "windows"

function detectPlatform(): Platform {
  const platform = (typeof process !== "undefined" && process.platform) || "linux"
  if (platform === "win32") return "windows"
  if (platform === "darwin") return "darwin"
  return "linux"
}

export class PathRegistry {
  private rules: PathRule[] = []
  private trustRules: PathRule[] = []
  private denyPatterns: string[] = []
  private platform: Platform

  constructor(platform?: Platform, rules?: PathRule[]) {
    this.platform = platform ?? detectPlatform()
    this.rules = rules ?? [...(DEFAULT_RULES[this.platform] ?? [])]
  }

  loadRules(rules: PathRule[]): void {
    this.rules = [...this.rules, ...rules]
  }

  loadFromData(data: Record<string, string[]>): void {
    const rules: PathRule[] = []
    for (const [level, patterns] of Object.entries(data)) {
      if (level in LEVEL_ORDER) {
        for (const pattern of patterns) {
          rules.push({ pattern, trustworthiness: level as Level, confidentiality: level as Level })
        }
      }
    }
    this.rules = [...this.rules, ...rules]
  }

  loadConfigRules(allowPaths: string[] = [], denyPaths: string[] = []): void {
    for (const path of allowPaths) {
      this.trustRules.push({ pattern: path, trustworthiness: "HIGH", confidentiality: "LOW" })
    }
    for (const path of denyPaths) {
      this.denyPatterns.push(path)
    }
  }

  classifyTrustworthiness(paths: string[]): Level {
    if (paths.length === 0) return "UNKNOWN"
    const absPaths = paths.filter(isClassifiable)
    if (absPaths.length === 0) return "UNKNOWN"

    for (const path of absPaths) {
      for (const pattern of this.denyPatterns) {
        if (path.startsWith(pattern) || globMatch(path, pattern)) {
          return "LOW"
        }
      }
    }

    let worst: Level = "UNKNOWN"
    for (const path of absPaths) {
      const level = this.trustForPath(path)
      if (worst === "UNKNOWN" || LEVEL_ORDER[level] < LEVEL_ORDER[worst]) {
        worst = level
      }
    }
    return worst
  }

  classifyConfidentiality(paths: string[]): Level {
    if (paths.length === 0) return "UNKNOWN"
    const absPaths = paths.filter(isClassifiable)
    if (absPaths.length === 0) return "UNKNOWN"

    let highest: Level = "UNKNOWN"
    for (const path of absPaths) {
      const level = this.confForPath(path)
      if (highest === "UNKNOWN" || LEVEL_ORDER[level] > LEVEL_ORDER[highest]) {
        highest = level
      }
    }
    return highest
  }

  private trustForPath(path: string): Level {
    for (const rule of this.rules) {
      if (rule.trustworthiness !== "UNKNOWN" && globMatch(path, rule.pattern)) {
        if (rule.trustworthiness === "LOW") return "LOW"
      }
    }
    for (const rule of this.rules) {
      if (rule.trustworthiness === "HIGH" && globMatch(path, rule.pattern)) {
        return "HIGH"
      }
    }
    return "UNKNOWN"
  }

  private confForPath(path: string): Level {
    for (const rule of this.rules) {
      if (rule.confidentiality === "HIGH" && globMatch(path, rule.pattern)) {
        return "HIGH"
      }
    }
    for (const rule of this.rules) {
      if (rule.confidentiality === "LOW" && globMatch(path, rule.pattern)) {
        return "LOW"
      }
    }
    return "UNKNOWN"
  }

  getPlatform(): Platform {
    return this.platform
  }
}
