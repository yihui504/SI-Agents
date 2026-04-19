/**
 * 运行状态管理模块
 * 用于管理和跟踪任务运行状态
 */

/**
 * 运行状态枚举
 */
export enum RunStatus {
  IDLE = "IDLE",
  RUNNING = "RUNNING",
  COMPLETED = "COMPLETED",
  ERROR = "ERROR",
}

/**
 * 运行信息接口
 */
export interface RunInfo {
  status: RunStatus
  startTime?: number
  endTime?: number
  error?: string
  metadata?: Record<string, unknown>
}

/**
 * 有效的状态转换映射
 * 定义了从每个状态可以转换到哪些状态
 */
const VALID_TRANSITIONS: Record<RunStatus, RunStatus[]> = {
  [RunStatus.IDLE]: [RunStatus.RUNNING],
  [RunStatus.RUNNING]: [RunStatus.COMPLETED, RunStatus.ERROR],
  [RunStatus.COMPLETED]: [RunStatus.IDLE, RunStatus.RUNNING],
  [RunStatus.ERROR]: [RunStatus.IDLE, RunStatus.RUNNING],
}

/**
 * 运行状态管理器
 * 用于管理任务的生命周期状态
 */
export class RunStatusManager {
  private status: RunStatus = RunStatus.IDLE
  private startTime?: number
  private endTime?: number
  private error?: string
  private metadata?: Record<string, unknown>

  /**
   * 获取当前状态
   */
  getStatus(): RunStatus {
    return this.status
  }

  /**
   * 获取完整的运行信息
   */
  getInfo(): RunInfo {
    return {
      status: this.status,
      startTime: this.startTime,
      endTime: this.endTime,
      error: this.error,
      metadata: this.metadata,
    }
  }

  /**
   * 检查是否可以进行状态转换
   */
  canTransitionTo(newStatus: RunStatus): boolean {
    const allowedTransitions = VALID_TRANSITIONS[this.status]
    return allowedTransitions.includes(newStatus)
  }

  /**
   * 开始运行
   * @param metadata 可选的元数据
   * @throws 如果当前状态不允许转换到 RUNNING
   */
  start(metadata?: Record<string, unknown>): void {
    if (!this.canTransitionTo(RunStatus.RUNNING)) {
      throw new Error(
        `Cannot start from current status: ${this.status}. ` +
          `Valid transitions from ${this.status}: ${VALID_TRANSITIONS[this.status].join(", ")}`
      )
    }

    this.status = RunStatus.RUNNING
    this.startTime = Date.now()
    this.endTime = undefined
    this.error = undefined
    this.metadata = metadata
  }

  /**
   * 完成运行
   * @param metadata 可选的元数据（会与现有元数据合并）
   * @throws 如果当前状态不允许转换到 COMPLETED
   */
  complete(metadata?: Record<string, unknown>): void {
    if (!this.canTransitionTo(RunStatus.COMPLETED)) {
      throw new Error(
        `Cannot complete from current status: ${this.status}. ` +
          `Valid transitions from ${this.status}: ${VALID_TRANSITIONS[this.status].join(", ")}`
      )
    }

    this.status = RunStatus.COMPLETED
    this.endTime = Date.now()
    if (metadata) {
      this.metadata = { ...this.metadata, ...metadata }
    }
  }

  /**
   * 运行失败
   * @param error 错误信息
   * @throws 如果当前状态不允许转换到 ERROR
   */
  fail(error: string): void {
    if (!this.canTransitionTo(RunStatus.ERROR)) {
      throw new Error(
        `Cannot fail from current status: ${this.status}. ` +
          `Valid transitions from ${this.status}: ${VALID_TRANSITIONS[this.status].join(", ")}`
      )
    }

    this.status = RunStatus.ERROR
    this.endTime = Date.now()
    this.error = error
  }

  /**
   * 重置状态到初始状态
   */
  reset(): void {
    this.status = RunStatus.IDLE
    this.startTime = undefined
    this.endTime = undefined
    this.error = undefined
    this.metadata = undefined
  }

  /**
   * 获取运行持续时间（毫秒）
   * @returns 运行时间，如果未开始或未结束则返回 undefined
   */
  getDuration(): number | undefined {
    if (this.startTime === undefined) {
      return undefined
    }
    const end = this.endTime ?? Date.now()
    return end - this.startTime
  }

  /**
   * 检查是否正在运行
   */
  isRunning(): boolean {
    return this.status === RunStatus.RUNNING
  }

  /**
   * 检查是否已完成
   */
  isCompleted(): boolean {
    return this.status === RunStatus.COMPLETED
  }

  /**
   * 检查是否出错
   */
  isError(): boolean {
    return this.status === RunStatus.ERROR
  }

  /**
   * 检查是否空闲
   */
  isIdle(): boolean {
    return this.status === RunStatus.IDLE
  }
}
