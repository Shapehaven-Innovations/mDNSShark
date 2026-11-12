import Testing
import Foundation
@testable import WidgetSnapshot

@Suite("Security basics")
struct SecurityBasicsTests {
    let t = Date(timeIntervalSince1970: 3_000_000)
    func c(_ s: Int, _ w: Int, _ cr: Int, _ p: Int) -> StatusCounts {
        StatusCounts(total: s + w + cr + p, secure: s, warning: w, critical: cr, pending: p)
    }

    @Test("All clear needs a secure device, no issues and nothing pending")
    func allClearNeedsSecure() {
        #expect(c(2, 0, 0, 0).isAllClear)
        #expect(!c(4, 0, 0, 1).isAllClear)
        #expect(!c(4, 1, 0, 0).isAllClear)
        #expect(!StatusCounts.zero.isAllClear)
    }

    @Test("verdicts follow issues, then pending, then secure")
    func verdicts() {
        #expect(StatusCounts.zero.securityVerdict == .noDevices)
        #expect(c(9, 2, 1, 0).securityVerdict == .issues(3))
        #expect(c(9, 0, 1, 2).securityVerdict == .issues(1))
        #expect(c(9, 0, 0, 2).securityVerdict == .checking(pending: 2))
        #expect(c(12, 0, 0, 0).securityVerdict == .allClear)
    }

    @Test("worst kind ranks critical, warning, pending, secure")
    func worst() {
        #expect(c(9, 2, 1, 0).worstKind == .critical)
        #expect(c(9, 2, 0, 1).worstKind == .warning)
        #expect(c(9, 0, 0, 2).worstKind == .pending)
        #expect(c(9, 0, 0, 0).worstKind == .secure)
        #expect(StatusCounts.zero.worstKind == nil)
    }

    @Test("legend keeps three kinds with zeros and adds pending only when present")
    func legend() {
        #expect(c(9, 0, 1, 0).legend == [.init(kind: .secure, count: 9), .init(kind: .warning, count: 0),
                                            .init(kind: .critical, count: 1)])
        #expect(c(9, 0, 0, 2).legend.last == .init(kind: .pending, count: 2))
    }

    @Test("short age", arguments: [(0.0, "just now"), (59, "just now"), (120, "2 min ago"), (3600, "1 hr ago"), (172_800, "2 d ago")])
    func shortAge(seconds: Double, text: String) {
        #expect(SnapshotFormatting.shortAge(since: t, now: t.addingTimeInterval(seconds)) == text)
    }

    @Test("issue phrase is singular only for one")
    func issuePhrase() {
        #expect(SnapshotFormatting.issuePhrase(0) == "0 issues")
        #expect(SnapshotFormatting.issuePhrase(1) == "1 issue")
        #expect(SnapshotFormatting.issuePhrase(3) == "3 issues")
    }

    @Test("the security link opens the Security tab")
    func link() { #expect(WidgetLink.securityTab.absoluteString == "mdnsshark://tab/security") }

    @Test("shared label for every verdict, with stale prefix and running suffix")
    func label() {
        func l(_ counts: StatusCounts, stale: Bool = false, running: Bool = false) -> String {
            SnapshotFormatting.securityAccessibilityLabel(counts: counts, scannedAt: t, now: t.addingTimeInterval(120),
                                                          isStale: stale, isScanRunning: running)
        }
        #expect(l(c(9, 2, 1, 0)) == "3 issues: 1 critical, 2 warning. 9 secure, scanned 2 minutes ago")
        #expect(l(c(12, 0, 0, 0)) == "All clear. 12 secure, scanned 2 minutes ago")
        #expect(l(c(9, 0, 0, 2)) == "0 issues, 2 still being checked. 9 secure, 2 pending, scanned 2 minutes ago")
        #expect(l(.zero) == "No devices found, scanned 2 minutes ago")
        #expect(l(c(9, 2, 1, 0), stale: true, running: true).hasPrefix("Out of date. 3 issues"))
        #expect(l(c(9, 2, 1, 0), stale: true, running: true).hasSuffix("scanned 2 minutes ago, scan running"))
    }
}
