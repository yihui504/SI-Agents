/**
 * RateLimiter - 滑动窗口速率限制器
 * 
 * 使用滑动窗口算法实现速率限制，支持配置最大调用次数和时间窗口
 */

export interface RateLimitConfig {
  max_calls_per_window: number
  window_seconds: number
}

export interface RateLimitResult {
  allowed: boolean
  remaining: number
  resetTime: number
  retryAfter?: number
}

interface TimestampEntry {
  timestamp: number
}

export class RateLimiter {
  private config: RateLimitConfig
  private calls: Map<string, TimestampEntry[]> = new Map()
  private cleanupInterval: ReturnType<typeof setInterval> | null = null

  constructor(config: RateLimitConfig) {
    this.config = {
      max_calls_per_window: config.max_calls_per_window ?? 100,
      window_seconds: config.window_seconds ?? 60,
    }
    
    // 启动定期清理过期记录的任务
    this.startCleanup()
  }

  /**
   * 检查是否允许调用
   * @param key 速率限制的键（如用户ID、工具名称等）
   * @returns 速率限制检查结果
   */
  checkLimit(key: string): RateLimitResult {
    const now = Date.now()
    const windowMs = this.config.window_seconds * 1000
    const windowStart = now - windowMs

    // 获取该键的调用记录
    let entries = this.calls.get(key) || []

    // 过滤掉窗口外的记录（滑动窗口）
    entries = entries.filter(entry => entry.timestamp > windowStart)

    // 计算当前窗口内的调用次数
    const currentCount = entries.length
    const remaining = Math.max(0, this.config.max_calls_per_window - currentCount)

    // 计算最早的调用何时过期（用于 resetTime）
    let resetTime: number
    if (entries.length > 0) {
      const oldestTimestamp = Math.min(...entries.map(e => e.timestamp))
      resetTime = oldestTimestamp + windowMs
    } else {
      resetTime = now + windowMs
    }

    // 检查是否超过限制
    if (currentCount >= this.config.max_calls_per_window) {
      const retryAfter = Math.ceil((resetTime - now) / 1000)
      return {
        allowed: false,
        remaining: 0,
        resetTime,
        retryAfter,
      }
    }

    // 记录本次调用
    entries.push({ timestamp: now })
    this.calls.set(key, entries)

    return {
      allowed: true,
      remaining: remaining - 1,
      resetTime,
    }
  }

  /**
   * 尝试执行操作（如果速率限制允许）
   * @param key 速率限制的键
   * @returns 是否允许执行
   */
  tryCall(key: string): boolean {
    const result = this.checkLimit(key)
    return result.allowed
  }

  /**
   * 获取当前键的调用统计
   * @param key 速率限制的键
   * @returns 当前窗口内的调用次数和剩余配额
   */
  getStats(key: string): { count: number; remaining: number; resetTime: number } {
    const now = Date.now()
    const windowMs = this.config.window_seconds * 1000
    const windowStart = now - windowMs

    let entries = this.calls.get(key) || []
    entries = entries.filter(entry => entry.timestamp > windowStart)

    const count = entries.length
    const remaining = Math.max(0, this.config.max_calls_per_window - count)

    let resetTime: number
    if (entries.length > 0) {
      const oldestTimestamp = Math.min(...entries.map(e => e.timestamp))
      resetTime = oldestTimestamp + windowMs
    } else {
      resetTime = now + windowMs
    }

    return { count, remaining, resetTime }
  }

  /**
   * 重置指定键的调用记录
   * @param key 速率限制的键
   */
  reset(key: string): void {
    this.calls.delete(key)
  }

  /**
   * 重置所有调用记录
   */
  resetAll(): void {
    this.calls.clear()
  }

  /**
   * 获取配置
   */
  getConfig(): RateLimitConfig {
    return { ...this.config }
  }

  /**
   * 更新配置
   * @param config 新的配置
   */
  updateConfig(config: Partial<RateLimitConfig>): void {
    this.config = {
      ...this.config,
      ...config,
    }
  }

  /**
   * 启动定期清理任务
   */
  private startCleanup(): void {
    // 每分钟清理一次过期记录
    this.cleanupInterval = setInterval(() => {
      this.cleanup()
    }, 60000)
  }

  /**
   * 清理过期的调用记录
   */
  private cleanup(): void {
    const now = Date.now()
    const windowMs = this.config.window_seconds * 1000
    const cutoff = now - windowMs * 2 // 保留两倍窗口时间的记录以防止边界问题

    for (const [key, entries] of this.calls.entries()) {
      const filtered = entries.filter(entry => entry.timestamp > cutoff)
      if (filtered.length === 0) {
        this.calls.delete(key)
      } else if (filtered.length !== entries.length) {
        this.calls.set(key, filtered)
      }
    }
  }

  /**
   * 销毁速率限制器，停止清理任务
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval)
      this.cleanupInterval = null
    }
    this.calls.clear()
  }
}

/**
 * 创建全局默认速率限制器
 */
let defaultRateLimiter: RateLimiter | null = null

export function getDefaultRateLimiter(): RateLimiter | null {
  return defaultRateLimiter
}

export function setDefaultRateLimiter(limiter: RateLimiter | null): void {
  if (defaultRateLimiter) {
    defaultRateLimiter.destroy()
  }
  defaultRateLimiter = limiter
}

export function createRateLimiter(config: RateLimitConfig): RateLimiter {
  return new RateLimiter(config)
}
