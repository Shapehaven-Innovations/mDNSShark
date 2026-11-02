import Testing
import Foundation
@testable import WidgetSnapshot

@Suite("Staleness")
struct StalenessTests {
    let t0 = Date(timeIntervalSince1970: 1_000_000)
    @Test("fresh under 60 minutes, stale at 60") func fresh() {
        #expect(Staleness.isFresh(scannedAt: t0, now: t0 + 3599))
        #expect(!Staleness.isFresh(scannedAt: t0, now: t0 + 3600))
    }
    @Test("ring fraction at 0, 30, 59 and 61 minutes") func ring() {
        #expect(Staleness.ringFraction(scannedAt: t0, now: t0) == 1)
        #expect(Staleness.ringFraction(scannedAt: t0, now: t0 + 30 * 60) == 0.5)
        #expect(abs(Staleness.ringFraction(scannedAt: t0, now: t0 + 59 * 60) - 1.0 / 60) < 1e-9)
        #expect(Staleness.ringFraction(scannedAt: t0, now: t0 + 61 * 60) == 0)
        #expect(Staleness.ringFraction(scannedAt: t0 + 60, now: t0) == 1)
    }
    @Test("new within 24 h, not at 24 h") func new() {
        #expect(Staleness.isNew(firstSeen: t0, now: t0 + 86_399))
        #expect(!Staleness.isNew(firstSeen: t0, now: t0 + 86_400))
    }
}
