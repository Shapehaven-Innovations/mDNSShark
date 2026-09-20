import XCTest
@testable import DeviceFingerprint

final class UDPSendPacerTests: XCTestCase {
    func test_enforcesMinimumSpacingBetweenTurns() async {
        let pacer = UDPSendPacer(minimumSpacing: .milliseconds(15))
        var timestamps: [ContinuousClock.Instant] = []
        let clock = ContinuousClock()

        for _ in 0..<5 {
            await pacer.waitTurn()
            timestamps.append(clock.now)
        }

        for i in 1..<timestamps.count {
            let gap = timestamps[i] - timestamps[i - 1]
            XCTAssertGreaterThanOrEqual(gap, .milliseconds(15))
        }
    }

    func test_enforcesMinimumSpacing_underConcurrentCallers() async {
        let pacer = UDPSendPacer(minimumSpacing: .milliseconds(15))
        let clock = ContinuousClock()

        let timestamps = await withTaskGroup(of: ContinuousClock.Instant.self) { group in
            for _ in 0..<10 {
                group.addTask {
                    await pacer.waitTurn()
                    return clock.now
                }
            }
            var results: [ContinuousClock.Instant] = []
            for await t in group { results.append(t) }
            return results
        }

        let sorted = timestamps.sorted()
        for i in 1..<sorted.count {
            let gap = sorted[i] - sorted[i - 1]
            XCTAssertGreaterThanOrEqual(gap, .milliseconds(15))
        }
    }

    func test_cancelledCaller_returnsPromptlyWithoutBusySpinning() async {
        // A generous spacing so that, if the old busy-spin bug were present,
        // a cancelled caller would burn CPU in a tight loop for roughly this
        // long before finally returning — making the regression obvious.
        let pacer = UDPSendPacer(minimumSpacing: .milliseconds(200))
        let clock = ContinuousClock()

        // Prime the pacer so every subsequent caller must actually wait for a
        // slot (and therefore hits the Task.sleep/cancellation path below).
        await pacer.waitTurn()

        let batchStart = clock.now

        await withTaskGroup(of: Duration.self) { group in
            for _ in 0..<4 {
                group.addTask {
                    let callStart = clock.now
                    await pacer.waitTurn()
                    return clock.now - callStart
                }
            }
            // Cancel every child task before any of them could legitimately
            // reach its 200ms slot, so a prompt return can only be explained
            // by the cancellation short-circuit, not by the spacing elapsing.
            group.cancelAll()

            for await elapsed in group {
                XCTAssertLessThan(
                    elapsed, .milliseconds(50),
                    "cancelled waitTurn() call took \(elapsed) — should return almost immediately, not busy-spin until its slot"
                )
            }
        }

        // Indirect evidence the actor wasn't busy-spinning: the whole batch
        // of 4 cancelled callers completed well under the 200ms spacing.
        let batchElapsed = clock.now - batchStart
        XCTAssertLessThan(
            batchElapsed, .milliseconds(100),
            "cancelled batch took \(batchElapsed) — suggests busy-spinning instead of an immediate cancellation return"
        )
    }
}
