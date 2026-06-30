import { URL } from "node:url"

const BLOCKED_HOSTS = [
  "169.254.169.254",
  "metadata.google.internal",
  "metadata.azure.com",
  "100.100.100.200",
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "[::1]",
]

const BLOCKED_RANGES = [
  { start: "10.0.0.0", end: "10.255.255.255" },
  { start: "172.16.0.0", end: "172.31.255.255" },
  { start: "192.168.0.0", end: "192.168.255.255" },
  { start: "fc00::", end: "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" },
  { start: "fe80::", end: "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff" },
]

function ipToNumber(ip: string): number {
  const parts = ip.split(".").map(Number)
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
}

function isPrivateIP(ip: string): boolean {
  for (const range of BLOCKED_RANGES) {
    try {
      const start = ipToNumber(range.start)
      const end = ipToNumber(range.end)
      const target = ipToNumber(ip)
      if (target >= start && target <= end) return true
    } catch {
      continue
    }
  }
  return false
}

function isNumericIP(hostname: string): string | null {
  if (/^\d+$/.test(hostname)) {
    const num = parseInt(hostname, 10)
    if (num >= 0 && num <= 0xFFFFFFFF) {
      return [
        (num >>> 24) & 0xFF,
        (num >>> 16) & 0xFF,
        (num >>> 8) & 0xFF,
        num & 0xFF,
      ].join(".")
    }
  }

  const octalMatch = hostname.match(/^(0[0-7]+)\.(0[0-7]+)\.(0[0-7]+)\.(0[0-7]+)$/)
  if (octalMatch) {
    const octets = [octalMatch[1], octalMatch[2], octalMatch[3], octalMatch[4]].map(s => parseInt(s, 8))
    if (octets.every(o => o >= 0 && o <= 255)) {
      return octets.join(".")
    }
  }

  const hexMatch = hostname.match(/^0x([0-9a-fA-F]+)$/)
  if (hexMatch) {
    const num = parseInt(hexMatch[1], 16)
    if (num >= 0 && num <= 0xFFFFFFFF) {
      return [
        (num >>> 24) & 0xFF,
        (num >>> 16) & 0xFF,
        (num >>> 8) & 0xFF,
        num & 0xFF,
      ].join(".")
    }
  }

  return null
}

const DEFAULT_BLOCKED_REBINDING_DOMAINS = [
  "rebinder.attacker.com",
  "ssrf.rfi.to",
  "1u.ms",
  "ssrf.sh",
]

export interface SSRFGuardConfig {
  enabled: boolean
  allowedProtocols: string[]
  blockedHosts: string[]
  allowPrivateIPs: boolean
  blockedRebindingDomains: string[]
}

export const DEFAULT_SSRF_CONFIG: SSRFGuardConfig = {
  enabled: true,
  allowedProtocols: ["https:", "http:"],
  blockedHosts: [],
  allowPrivateIPs: false,
  blockedRebindingDomains: [],
}

export function checkSSRF(urlStr: string, config: SSRFGuardConfig = DEFAULT_SSRF_CONFIG): { allowed: boolean; reason: string | null } {
  if (!config.enabled) return { allowed: true, reason: null }

  let parsedUrl: URL
  try {
    parsedUrl = new URL(urlStr)
  } catch {
    return { allowed: false, reason: "Invalid URL format" }
  }

  if (!config.allowedProtocols.includes(parsedUrl.protocol)) {
    return { allowed: false, reason: `Protocol "${parsedUrl.protocol}" not allowed` }
  }

  const hostname = parsedUrl.hostname.toLowerCase()

  const allBlockedHosts = [...BLOCKED_HOSTS, ...config.blockedHosts]
  for (const blocked of allBlockedHosts) {
    if (hostname === blocked || hostname.endsWith("." + blocked)) {
      return { allowed: false, reason: `Host "${hostname}" is blocked` }
    }
  }

  const numericIP = isNumericIP(hostname)
  if (numericIP) {
    for (const blocked of allBlockedHosts) {
      if (numericIP === blocked || numericIP.endsWith("." + blocked)) {
        return { allowed: false, reason: `Host "${hostname}" resolves to blocked IP "${numericIP}"` }
      }
    }
    if (!config.allowPrivateIPs && isPrivateIP(numericIP)) {
      return { allowed: false, reason: `Host "${hostname}" resolves to private IP "${numericIP}"` }
    }
  }

  const allRebindingDomains = [...DEFAULT_BLOCKED_REBINDING_DOMAINS, ...config.blockedRebindingDomains]
  for (const domain of allRebindingDomains) {
    if (hostname === domain || hostname.endsWith("." + domain)) {
      return { allowed: false, reason: `Host "${hostname}" is a known DNS rebinding domain` }
    }
  }

  if (!config.allowPrivateIPs && isPrivateIP(hostname)) {
    return { allowed: false, reason: `Private IP "${hostname}" is not allowed` }
  }

  return { allowed: true, reason: null }
}

// Redirect-based SSRF (e.g., an open redirect on an allowed host pointing to an internal IP)
// is out of scope for URL-level checking. Detecting it requires following the redirect at
// runtime and re-validating the resolved URL. This must be handled at the HTTP client layer.
