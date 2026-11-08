import Testing
import Foundation
@testable import WidgetSnapshot

@Suite("Security widget models")
struct SecurityWidgetModelTests {
    let scan = Date(timeIntervalSince1970: 5_000_000)
    func c(_ s: Int, _ w: Int, _ cr: Int, _ np: Int, _ p: Int) -> StatusCounts {
        StatusCounts(total: s + w + cr + np + p, secure: s, warning: w, critical: cr, notProbed: np, pending: p)
    }
    func snap(_ counts: StatusCounts) -> SnapshotDecodeResult<WidgetSnapshot> {
        .loaded(WidgetSnapshot(version: 1, scannedAt: scan, subnet: "192.168.1.0/24", counts: counts, typeCounts: [:],
                               history: [ScanSample(at: scan, counts: counts)], newDevices: [], topology: [],
                               topologyOverflow: 0, ownDeviceKey: nil))
    }
    func home(_ counts: StatusCounts, after: Double = 120, running: Bool = false) -> SecurityWidgetModel? {
        if case .loaded(let m) = SecurityWidgetModel.make(snap(counts), now: scan.addingTimeInterval(after), isScanRunning: running) { return m }
        return nil
    }
    func lock(_ counts: StatusCounts, after: Double = 120) -> SecurityAccessoryModel? {
        if case .loaded(let m) = SecurityAccessoryModel.make(snap(counts), now: scan.addingTimeInterval(after), isScanRunning: false) { return m }
        return nil
    }

    @Test("missing and newer map to no scan and needs update for both models")
    func states() {
        #expect(SecurityWidgetModel.make(.missing, now: scan, isScanRunning: false) == .noScan)
        #expect(SecurityAccessoryModel.make(.newer(version: 2), now: scan, isScanRunning: false) == .needsUpdate)
    }

    @Test("issues: hero count, worst symbol, literal grid and captions")
    func issuesHome() {
        let m = home(c(9, 2, 1, 3, 0))!
        #expect(m.hero == .count(3, unit: "issues") && m.headerSymbol == .critical)
        #expect(m.grid.map(\.count) == [9, 2, 1, 3] && m.grid.map(\.kind) == [.secure, .warning, .critical, .notProbed])
        #expect(m.smallCaption == "3 not probed · 2 min ago" && m.ageText == "Scanned 2 min ago")
        #expect(m.largeCaption == "3 not probed · Scanned 2 min ago" && m.checkingNote == nil)
    }

    @Test("all clear shows the title and still states not probed")
    func allClearSmall() {
        let m = home(c(12, 0, 0, 2, 0))!
        #expect(m.hero == .title("All clear") && m.headerSymbol == .secure)
        #expect(m.smallCaption == "2 not probed · 2 min ago")
    }

    @Test("pending blocks all clear and adds a checking note")
    func pendingBlocks() {
        let m = home(c(9, 0, 0, 3, 2))!
        #expect(m.hero == .count(0, unit: "issues") && m.checkingNote == "2 checking" && m.headerSymbol == .pending)
    }

    @Test("nothing probed never reads as secure")
    func nothingProbedNeverClear() {
        let m = home(c(0, 0, 0, 3, 0))!
        #expect(m.hero == .title("Not probed") && m.headerSymbol == .notProbed)
        #expect(lock(c(0, 0, 0, 3, 0))!.gaugeFraction == 0)
        #expect(!lock(c(0, 0, 0, 3, 0))!.inlineText.contains("All clear"))
    }

    @Test("stale is flagged and prefixed in every label")
    func stale() {
        let m = home(c(9, 2, 1, 3, 0), after: 3 * 3600)!
        #expect(m.isStale && m.accessibilityLabel.hasPrefix("Out of date. "))
        let a = lock(c(12, 0, 0, 2, 0), after: 3 * 3600)!
        #expect(a.isStale && a.stateSymbol == "clock" && a.rectTitle == "Out of date")
        #expect(a.inlineText == "Out of date, 0 issues" && a.inlineSymbol == "clock")
    }

    @Test("gauge is secure over probed, pending counted as not secure")
    func gauge() {
        #expect(lock(c(9, 2, 1, 3, 0))!.gaugeFraction == 0.75)
        #expect(lock(c(6, 0, 0, 3, 2))!.gaugeFraction == 0.75)
        #expect(lock(c(9, 2, 1, 3, 0))!.gaugeValue == 3 && lock(c(9, 2, 1, 3, 0))!.stateSymbol == "exclamationmark.shield")
    }

    @Test("inline texts per verdict, not probed always stated when fresh")
    func inlineTexts() {
        #expect(lock(c(9, 2, 1, 3, 0))!.inlineText == "3 issues, 3 not probed")
        #expect(lock(c(12, 0, 0, 2, 0))!.inlineText == "All clear, 2 not probed")
        #expect(lock(c(9, 0, 0, 3, 2))!.inlineText == "0 issues, 2 checking")
        #expect(lock(c(0, 0, 0, 3, 0))!.inlineText == "Not probed, 3 devices")
    }

    @Test("rectangular rows: issues first, then secure and not probed, pending appended")
    func rows() {
        let a = lock(c(9, 2, 1, 3, 1))!
        #expect(a.primaryRow.map(\.kind) == [.critical, .warning] && a.primaryRow.map(\.count) == [1, 2])
        #expect(a.secondaryRow.map(\.kind) == [.secure, .notProbed, .pending])
        #expect(a.rectTitle == "Security")
    }

    @Test("every shape's label comes from the shared formatter")
    func labelsShareFormatter() {
        let counts = c(9, 2, 1, 3, 0)
        let shared = SnapshotFormatting.securityAccessibilityLabel(counts: counts, scannedAt: scan,
                                                                   now: scan.addingTimeInterval(120), isStale: false, isScanRunning: false)
        #expect(home(counts)!.accessibilityLabel == shared)
        #expect(lock(counts)!.accessibilityLabel == shared)
        #expect(home(counts)!.largeAccessibilityLabel == shared + ". " + home(counts)!.chart.accessibilityLabel)
    }

    @Test("a running scan is spoken last, after the chart, on the large label")
    func largeRunningOrder() {
        let m = home(c(9, 2, 1, 3, 0), running: true)!
        #expect(m.accessibilityLabel.hasSuffix(", scan running"))
        #expect(m.largeAccessibilityLabel.hasSuffix(m.chart.accessibilityLabel + ", scan running"))
        #expect(!m.largeAccessibilityLabel.contains("scan running. Issues per scan"))
    }

    func btSnap(_ counts: StatusCounts) -> SnapshotDecodeResult<WidgetSnapshot> {
        guard case .loaded(var s) = snap(counts) else { return .missing }
        s.bluetooth = BluetoothSummary(scannedAt: scan.addingTimeInterval(-600), nearby: 7, suggested: 2)
        return .loaded(s)
    }
    let btClause = ". 7 Bluetooth devices nearby, 2 suggested as network devices, inferred, Bluetooth scanned 12 minutes ago, not security assessed"

    @Test("small, medium and large labels carry the Bluetooth clause ending not security assessed, before scan running")
    func securitySmallMediumLargeClauseEndsNotSecurityAssessed() {
        let counts = c(9, 2, 1, 3, 0), now = scan.addingTimeInterval(120)
        let shared = SnapshotFormatting.securityAccessibilityLabel(counts: counts, scannedAt: scan, now: now, isStale: false, isScanRunning: false)
        guard case .loaded(let m) = SecurityWidgetModel.make(btSnap(counts), now: now, isScanRunning: true) else { Issue.record("not loaded"); return }
        #expect(m.bluetooth?.securityLineText == "7 nearby · not assessed · 12 min ago")
        #expect(m.accessibilityLabel == shared + btClause + ", scan running")
        #expect(m.largeAccessibilityLabel == shared + ". " + m.chart.accessibilityLabel + btClause + ", scan running")
        guard case .loaded(let idle) = SecurityWidgetModel.make(btSnap(counts), now: now, isScanRunning: false) else { Issue.record("not loaded"); return }
        #expect(idle.accessibilityLabel.hasSuffix("not security assessed"))
        #expect(home(counts)!.bluetooth == nil)
    }

    @Test("circular, rectangular and inline share a label that carries the Bluetooth clause")
    func accessoryCircularRectangularInlineCarryClause() {
        let counts = c(9, 2, 1, 3, 0), now = scan.addingTimeInterval(120)
        let shared = SnapshotFormatting.securityAccessibilityLabel(counts: counts, scannedAt: scan, now: now, isStale: false, isScanRunning: false)
        guard case .loaded(let a) = SecurityAccessoryModel.make(btSnap(counts), now: now, isScanRunning: true) else { Issue.record("not loaded"); return }
        #expect(a.bluetooth?.nearby == 7)
        #expect(a.accessibilityLabel == shared + btClause + ", scan running")
        guard case .loaded(let idle) = SecurityAccessoryModel.make(btSnap(counts), now: now, isScanRunning: false) else { Issue.record("not loaded"); return }
        #expect(idle.accessibilityLabel == shared + btClause)
        #expect(lock(counts)!.bluetooth == nil)
    }
}
