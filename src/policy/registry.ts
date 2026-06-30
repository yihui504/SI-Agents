import type { PolicyRegistryEntry } from "../types/policy.ts"
import type { Policy } from "./policy.ts"

export class PolicyRegistry {
  private entries: PolicyRegistryEntry[] = []
  private instances: Map<string, Policy> = new Map()

  register(entry: PolicyRegistryEntry, instance: Policy): void {
    this.entries.push(entry)
    this.instances.set(entry.name, instance)
  }

  getEnabledPolicies(): Policy[] {
    return this.entries
      .filter((e) => e.enabled)
      .sort((a, b) => (a.order ?? 100) - (b.order ?? 100))
      .map((e) => this.instances.get(e.name))
      .filter((p): p is Policy => p !== undefined)
  }

  getAllPolicies(): Policy[] {
    return this.entries
      .map((e) => this.instances.get(e.name))
      .filter((p): p is Policy => p !== undefined)
  }

  getEntry(name: string): PolicyRegistryEntry | undefined {
    return this.entries.find((e) => e.name === name)
  }

  setEnabled(name: string, enabled: boolean): void {
    const entry = this.entries.find((e) => e.name === name)
    if (entry) {
      entry.enabled = enabled
    }
  }

  getEntries(): PolicyRegistryEntry[] {
    return [...this.entries].sort((a, b) => (a.order ?? 100) - (b.order ?? 100))
  }
}
