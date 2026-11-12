import Testing
import Foundation
@testable import WidgetSnapshot

@Suite("Snapshot formatting")
struct SnapshotFormattingTests {
    let t0 = Date(timeIntervalSince1970: 1_000_000)

    @Test("relative ages") func ages() {
        #expect(SnapshotFormatting.age(since: t0, now: t0 + 30) == "just now")
        #expect(SnapshotFormatting.age(since: t0, now: t0 + 60) == "1 minute ago")
        #expect(SnapshotFormatting.age(since: t0, now: t0 + 12 * 60 + 59) == "12 minutes ago")
        #expect(SnapshotFormatting.age(since: t0, now: t0 + 3600) == "1 hour ago")
        #expect(SnapshotFormatting.age(since: t0, now: t0 + 5 * 3600) == "5 hours ago")
        #expect(SnapshotFormatting.age(since: t0, now: t0 + 3 * 86_400) == "3 days ago")
        #expect(SnapshotFormatting.age(since: t0 + 10, now: t0) == "just now")
    }
    @Test("bytes") func bytes() {
        #expect(SnapshotFormatting.bytes(0) == "0 B")
        #expect(SnapshotFormatting.bytes(999) == "999 B")
        #expect(SnapshotFormatting.bytes(640_000) == "640 KB")
        #expect(SnapshotFormatting.bytes(2_100_000) == "2.1 MB")
        #expect(SnapshotFormatting.bytes(3_250_000_000) == "3.3 GB")
    }
    @Test("rounding promotes instead of printing 1000") func bytesPromoteAtBoundary() {
        #expect(SnapshotFormatting.bytes(999_499) == "999 KB")
        #expect(SnapshotFormatting.bytes(999_500) == "1.0 MB")
        #expect(SnapshotFormatting.bytes(999_960_000) == "1.0 GB")
    }
    @Test("whole-number percents sum to 100") func percents() {
        let p = SnapshotFormatting.wholePercents(["HTTPS": 33.4, "TCP": 33.3, "DNS": 33.3])
        #expect(p.values.reduce(0, +) == 100)
        #expect(p == ["HTTPS": 34, "TCP": 33, "DNS": 33])
        #expect(SnapshotFormatting.wholePercents(["A": 1, "B": 3]) == ["A": 25, "B": 75])
        #expect(SnapshotFormatting.wholePercents(["A": 0]) == [:])
        #expect(SnapshotFormatting.wholePercents([:]) == [:])
    }
    @Test("All clear only with zero warning, critical and pending") func allClear() {
        #expect(StatusCounts(total: 5, secure: 2, warning: 0, critical: 0, pending: 0).isAllClear)
        #expect(!StatusCounts(total: 5, secure: 4, warning: 0, critical: 0, pending: 1).isAllClear)
        #expect(!StatusCounts(total: 5, secure: 4, warning: 1, critical: 0, pending: 0).isAllClear)
        #expect(!StatusCounts.zero.isAllClear)
        #expect(!StatusCounts(total: 3, secure: 0, warning: 0, critical: 0, pending: 0).isAllClear)
        #expect(StatusCounts(total: 5, secure: 0, warning: 2, critical: 1, pending: 0).issues == 3)
    }
    @Test("VoiceOver label") func label() {
        let c = StatusCounts(total: 14, secure: 9, warning: 2, critical: 1, pending: 0)
        #expect(SnapshotFormatting.accessibilityLabel(counts: c, scannedAt: t0, now: t0 + 12 * 60)
                == "14 devices, 9 secure, 2 warning, 1 critical, scanned 12 minutes ago")
        let one = StatusCounts(total: 1, secure: 0, warning: 0, critical: 0, pending: 1)
        #expect(SnapshotFormatting.accessibilityLabel(counts: one, scannedAt: t0, now: t0)
                == "1 device, 0 secure, 0 warning, 0 critical, 1 pending, scanned just now")
    }
}
