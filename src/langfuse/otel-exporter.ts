export interface OTLPConfig {
  endpoint: string
  headers?: Record<string, string>
  serviceName?: string
}

interface OTLPSpan {
  traceId: string
  spanId: string
  name: string
  kind: number
  startTimeUnixNano: string
  endTimeUnixNano: string
  attributes: Array<{ key: string; value: { stringValue: string } }>
  status?: { code: number }
}

export class OTLPExporter {
  private config: OTLPConfig

  constructor(config: OTLPConfig) {
    this.config = config
  }

  async exportSpan(span: OTLPSpan): Promise<boolean> {
    try {
      const payload = {
        resourceSpans: [{
          resource: {
            attributes: [
              { key: "service.name", value: { stringValue: this.config.serviceName ?? "si-agents" } },
            ],
          },
          scopeSpans: [{ spans: [span] }],
        }],
      }
      const response = await fetch(this.config.endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...this.config.headers,
        },
        body: JSON.stringify(payload),
      })
      return response.ok
    } catch {
      return false
    }
  }

  createSpan(options: {
    traceId: string
    name: string
    startTime: Date
    endTime?: Date
    attributes?: Record<string, string>
  }): OTLPSpan {
    const spanId = crypto.randomUUID().replace(/-/g, "").slice(0, 16)
    return {
      traceId: options.traceId.replace(/-/g, "").padEnd(32, "0").slice(0, 32),
      spanId,
      name: options.name,
      kind: 1,
      startTimeUnixNano: String(options.startTime.getTime() * 1_000_000),
      endTimeUnixNano: options.endTime ? String(options.endTime.getTime() * 1_000_000) : String(Date.now() * 1_000_000),
      attributes: Object.entries(options.attributes ?? {}).map(([key, value]) => ({
        key,
        value: { stringValue: value },
      })),
    }
  }
}
