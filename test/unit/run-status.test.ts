import { describe, it, expect, beforeEach } from "bun:test"
import { RunStatus, RunStatusManager } from "../../src/optimize/run-status.ts"

describe("RunStatus", () => {
  it("should have correct enum values", () => {
    expect(RunStatus.IDLE).toBe("IDLE")
    expect(RunStatus.RUNNING).toBe("RUNNING")
    expect(RunStatus.COMPLETED).toBe("COMPLETED")
    expect(RunStatus.ERROR).toBe("ERROR")
  })
})

describe("RunStatusManager", () => {
  let manager: RunStatusManager

  beforeEach(() => {
    manager = new RunStatusManager()
  })

  describe("initial state", () => {
    it("should start with IDLE status", () => {
      expect(manager.getStatus()).toBe(RunStatus.IDLE)
    })

    it("should return correct initial info", () => {
      const info = manager.getInfo()
      expect(info.status).toBe(RunStatus.IDLE)
      expect(info.startTime).toBeUndefined()
      expect(info.endTime).toBeUndefined()
      expect(info.error).toBeUndefined()
      expect(info.metadata).toBeUndefined()
    })

    it("should be idle initially", () => {
      expect(manager.isIdle()).toBe(true)
      expect(manager.isRunning()).toBe(false)
      expect(manager.isCompleted()).toBe(false)
      expect(manager.isError()).toBe(false)
    })
  })

  describe("start()", () => {
    it("should transition from IDLE to RUNNING", () => {
      manager.start()
      expect(manager.getStatus()).toBe(RunStatus.RUNNING)
      expect(manager.isRunning()).toBe(true)
    })

    it("should set startTime when starting", () => {
      const before = Date.now()
      manager.start()
      const after = Date.now()
      expect(manager.getInfo().startTime).toBeGreaterThanOrEqual(before)
      expect(manager.getInfo().startTime).toBeLessThanOrEqual(after)
    })

    it("should clear endTime and error when starting", () => {
      manager.start()
      manager.fail("test error")
      manager.reset()
      manager.start()
      expect(manager.getInfo().endTime).toBeUndefined()
      expect(manager.getInfo().error).toBeUndefined()
    })

    it("should store metadata when provided", () => {
      const metadata = { taskId: "123", user: "test" }
      manager.start(metadata)
      expect(manager.getInfo().metadata).toEqual(metadata)
    })

    it("should throw error when starting from RUNNING", () => {
      manager.start()
      expect(() => manager.start()).toThrow("Cannot start from current status: RUNNING")
    })

    it("should allow starting from COMPLETED (restart)", () => {
      manager.start()
      manager.complete()
      expect(() => manager.start()).not.toThrow()
      expect(manager.getStatus()).toBe(RunStatus.RUNNING)
    })
  })

  describe("complete()", () => {
    it("should transition from RUNNING to COMPLETED", () => {
      manager.start()
      manager.complete()
      expect(manager.getStatus()).toBe(RunStatus.COMPLETED)
      expect(manager.isCompleted()).toBe(true)
    })

    it("should set endTime when completing", () => {
      manager.start()
      const before = Date.now()
      manager.complete()
      const after = Date.now()
      expect(manager.getInfo().endTime).toBeGreaterThanOrEqual(before)
      expect(manager.getInfo().endTime).toBeLessThanOrEqual(after)
    })

    it("should merge metadata when provided", () => {
      manager.start({ taskId: "123" })
      manager.complete({ result: "success" })
      expect(manager.getInfo().metadata).toEqual({ taskId: "123", result: "success" })
    })

    it("should throw error when completing from IDLE", () => {
      expect(() => manager.complete()).toThrow("Cannot complete from current status: IDLE")
    })

    it("should throw error when completing from COMPLETED", () => {
      manager.start()
      manager.complete()
      expect(() => manager.complete()).toThrow("Cannot complete from current status: COMPLETED")
    })

    it("should throw error when completing from ERROR", () => {
      manager.start()
      manager.fail("error")
      expect(() => manager.complete()).toThrow("Cannot complete from current status: ERROR")
    })
  })

  describe("fail()", () => {
    it("should transition from RUNNING to ERROR", () => {
      manager.start()
      manager.fail("Something went wrong")
      expect(manager.getStatus()).toBe(RunStatus.ERROR)
      expect(manager.isError()).toBe(true)
    })

    it("should store error message", () => {
      manager.start()
      manager.fail("Test error message")
      expect(manager.getInfo().error).toBe("Test error message")
    })

    it("should set endTime when failing", () => {
      manager.start()
      const before = Date.now()
      manager.fail("error")
      const after = Date.now()
      expect(manager.getInfo().endTime).toBeGreaterThanOrEqual(before)
      expect(manager.getInfo().endTime).toBeLessThanOrEqual(after)
    })

    it("should throw error when failing from IDLE", () => {
      expect(() => manager.fail("error")).toThrow("Cannot fail from current status: IDLE")
    })

    it("should throw error when failing from COMPLETED", () => {
      manager.start()
      manager.complete()
      expect(() => manager.fail("error")).toThrow("Cannot fail from current status: COMPLETED")
    })

    it("should throw error when failing from ERROR", () => {
      manager.start()
      manager.fail("first error")
      expect(() => manager.fail("second error")).toThrow("Cannot fail from current status: ERROR")
    })
  })

  describe("reset()", () => {
    it("should reset to IDLE from any state", () => {
      manager.start()
      manager.complete()
      manager.reset()
      expect(manager.getStatus()).toBe(RunStatus.IDLE)
    })

    it("should clear all fields on reset", () => {
      manager.start({ key: "value" })
      manager.fail("error")
      manager.reset()
      const info = manager.getInfo()
      expect(info.status).toBe(RunStatus.IDLE)
      expect(info.startTime).toBeUndefined()
      expect(info.endTime).toBeUndefined()
      expect(info.error).toBeUndefined()
      expect(info.metadata).toBeUndefined()
    })

    it("should allow starting again after reset", () => {
      manager.start()
      manager.fail("error")
      manager.reset()
      expect(() => manager.start()).not.toThrow()
      expect(manager.getStatus()).toBe(RunStatus.RUNNING)
    })
  })

  describe("canTransitionTo()", () => {
    it("should return true for valid transitions", () => {
      expect(manager.canTransitionTo(RunStatus.RUNNING)).toBe(true)
      manager.start()
      expect(manager.canTransitionTo(RunStatus.COMPLETED)).toBe(true)
      expect(manager.canTransitionTo(RunStatus.ERROR)).toBe(true)
    })

    it("should return false for invalid transitions from IDLE", () => {
      expect(manager.canTransitionTo(RunStatus.COMPLETED)).toBe(false)
      expect(manager.canTransitionTo(RunStatus.ERROR)).toBe(false)
      expect(manager.canTransitionTo(RunStatus.IDLE)).toBe(false)
    })

    it("should allow restart from COMPLETED", () => {
      manager.start()
      manager.complete()
      expect(manager.canTransitionTo(RunStatus.RUNNING)).toBe(true)
      expect(manager.canTransitionTo(RunStatus.IDLE)).toBe(true)
    })

    it("should allow restart from ERROR", () => {
      manager.start()
      manager.fail("error")
      expect(manager.canTransitionTo(RunStatus.RUNNING)).toBe(true)
      expect(manager.canTransitionTo(RunStatus.IDLE)).toBe(true)
    })
  })

  describe("getDuration()", () => {
    it("should return undefined when not started", () => {
      expect(manager.getDuration()).toBeUndefined()
    })

    it("should return elapsed time when running", () => {
      manager.start()
      const duration = manager.getDuration()
      expect(duration).toBeGreaterThanOrEqual(0)
    })

    it("should return total duration when completed", () => {
      manager.start()
      // Small delay to ensure measurable duration
      const start = manager.getInfo().startTime!
      manager.complete()
      const duration = manager.getDuration()
      expect(duration).toBe(manager.getInfo().endTime! - start)
    })
  })

  describe("full lifecycle", () => {
    it("should support IDLE -> RUNNING -> COMPLETED flow", () => {
      expect(manager.getStatus()).toBe(RunStatus.IDLE)

      manager.start({ task: "test" })
      expect(manager.getStatus()).toBe(RunStatus.RUNNING)
      expect(manager.isRunning()).toBe(true)

      manager.complete({ result: "done" })
      expect(manager.getStatus()).toBe(RunStatus.COMPLETED)
      expect(manager.isCompleted()).toBe(true)

      const info = manager.getInfo()
      expect(info.startTime).toBeDefined()
      expect(info.endTime).toBeDefined()
      expect(info.metadata).toEqual({ task: "test", result: "done" })
    })

    it("should support IDLE -> RUNNING -> ERROR flow", () => {
      manager.start()
      manager.fail("Something failed")
      expect(manager.getStatus()).toBe(RunStatus.ERROR)
      expect(manager.getInfo().error).toBe("Something failed")
    })

    it("should support restart after completion", () => {
      manager.start()
      manager.complete()
      manager.reset()
      manager.start()
      expect(manager.getStatus()).toBe(RunStatus.RUNNING)
    })

    it("should support restart after error", () => {
      manager.start()
      manager.fail("error")
      manager.reset()
      manager.start()
      manager.complete()
      expect(manager.getStatus()).toBe(RunStatus.COMPLETED)
    })
  })
})
