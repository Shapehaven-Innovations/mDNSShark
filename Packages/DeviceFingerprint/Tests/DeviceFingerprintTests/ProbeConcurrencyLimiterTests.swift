// Packages/DeviceFingerprint/Tests/DeviceFingerprintTests/ProbeConcurrencyLimiterTests.swift
import XCTest
@testable import DeviceFingerprint

final class ProbeConcurrencyLimiterTests: XCTestCase {
    func test_neverExceedsCapUnderConcurrentLoad() async {
        let limiter = ProbeConcurrencyLimiter(maxConcurrent: 4)
        let counter = ObservedConcurrency()

        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<50 {
                group.addTask {
                    await limiter.acquire()
                    await counter.increment()
                    try? await Task.sleep(nanoseconds: 1_000_000) // 1ms of simulated "work"
                    await counter.decrement()
                    await limiter.release()
                }
            }
        }

        let maxObserved = await counter.maxSeen
        XCTAssertLessThanOrEqual(maxObserved, 4)
    }

    /// Regression test for the hand-off-semantics bug: with the old
    /// `acquire()`/`release()` (release decrements `current`, resumes a
    /// waiter, and only the waiter's own re-entry into the actor increments
    /// `current` again), there was a window between a waiter being resumed
    /// and it actually re-entering the actor where another queued
    /// `acquire()` could also observe a free slot — transiently exceeding
    /// `maxConcurrent`. Unlike the single-burst test above, this sustains
    /// contention across many acquire/release cycles with more callers than
    /// the cap and a hold time long enough that callers reliably queue as
    /// waiters (not just win a free slot outright), which is the regime
    /// that actually exercises that race.
    func test_neverExceedsCapUnderSustainedContentionWithWaiters() async {
        let limiter = ProbeConcurrencyLimiter(maxConcurrent: 4)
        let counter = ObservedConcurrency()

        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<20 {
                group.addTask {
                    for _ in 0..<5 {
                        await limiter.acquire()
                        await counter.increment()
                        try? await Task.sleep(nanoseconds: 2_000_000) // 2ms hold
                        await counter.decrement()
                        await limiter.release()
                    }
                }
            }
        }

        let maxObserved = await counter.maxSeen
        XCTAssertLessThanOrEqual(maxObserved, 4)
    }
}

/// Test-only helper: tracks the high-water mark of concurrently "running" work.
actor ObservedConcurrency {
    private(set) var current = 0
    private(set) var maxSeen = 0
    func increment() { current += 1; maxSeen = max(maxSeen, current) }
    func decrement() { current -= 1 }
}
