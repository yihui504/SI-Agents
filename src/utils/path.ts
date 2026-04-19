import { homedir } from "node:os"

export function expandPath(path: string): string {
  if (path.startsWith("~")) {
    return path.replace("~", homedir())
  }
  return path
}
