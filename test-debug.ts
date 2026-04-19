import { PathRegistry } from "./src/taint/path-registry.ts"
import { LEVEL_ORDER } from "./src/types/instruction.ts"

class DebugPathRegistry extends PathRegistry {
  debugClassifyTrustworthiness(paths: string[]): string {
    if (paths.length === 0) return "UNKNOWN"
    
    const URL_PREFIXES = ["http://", "https://", "ftp://", "ftps://"]
    const absPaths = paths.filter(p => {
      const norm = p.replace(/\\/g, "/")
      if (norm.startsWith("/")) return true
      if (norm.startsWith("~/")) return true
      for (const prefix of URL_PREFIXES) {
        if (norm.startsWith(prefix)) return true
      }
      if (norm.length >= 3 && norm[1] === ":" && norm[2] === "/" && /[a-zA-Z]/.test(norm[0])) return true
      return false
    })
    
    console.log("absPaths:", absPaths)
    
    if (absPaths.length === 0) return "UNKNOWN"

    let worst: string = "UNKNOWN"
    for (const path of absPaths) {
      const level = (this as unknown as { trustForPath: (p: string) => string }).trustForPath(path)
      console.log(`  Path: ${path}, Level: ${level}, LEVEL_ORDER[level]: ${LEVEL_ORDER[level as keyof typeof LEVEL_ORDER]}, LEVEL_ORDER[worst]: ${LEVEL_ORDER[worst as keyof typeof LEVEL_ORDER]}`)
      if (LEVEL_ORDER[level as keyof typeof LEVEL_ORDER] < LEVEL_ORDER[worst as keyof typeof LEVEL_ORDER]) {
        worst = level
      }
    }
    return worst
  }
}

const registry = new DebugPathRegistry()
const testPath = "https://example.com/data"

console.log("LEVEL_ORDER:", LEVEL_ORDER)
console.log("\ndebugClassifyTrustworthiness:")
const result = registry.debugClassifyTrustworthiness([testPath])
console.log("Result:", result)

console.log("\nOriginal classifyTrustworthiness:", registry.classifyTrustworthiness([testPath]))
