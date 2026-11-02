import Testing
import Foundation
@testable import WidgetSnapshot

@Suite("Widget models")
struct WidgetModelsTests {
    let scan = Date(timeIntervalSince1970: 2_000_000)
    let counts = StatusCounts(total: 14, secure: 9, warning: 2, critical: 1, notProbed: 2, pending: 0)

    func snapshot(_ c: StatusCounts? = nil, history: [ScanSample] = [], subnet: String? = "192.168.1.0/24") -> WidgetSnapshot {
        WidgetSnapshot(version: 1, scannedAt: scan, subnet: subnet, counts: c ?? counts, typeCounts: [:], history: history,
                       newDevices: [], topology: [], topologyOverflow: 0, ownDeviceKey: nil)
    }

    @Test("capsule keeps status order, omits zeros, and outlines not probed and pending")
    func capsuleSegmentsInOrder() {
        let c = StatusCounts(total: 6, secure: 0, warning: 2, critical: 1, notProbed: 2, pending: 1)
        #expect(c.capsuleSegments.map(\.kind) == [.warning, .critical, .notProbed, .pending])
        #expect(c.capsuleSegments.map(\.count) == [2, 1, 2, 1])
        #expect(c.capsuleSegments.filter(\.kind.isOutlined).map(\.kind) == [.notProbed, .pending])
        #expect(StatusCounts.zero.capsuleSegments.isEmpty)
    }

    @Test("missing and newer files map to no scan and needs update")
    func states() {
        #expect(DevicesWidgetModel.make(.missing, now: scan, isScanRunning: false) == .noScan)
        #expect(ScanNowWidgetModel.make(.newer(version: 2), now: scan, isScanRunning: false) == .needsUpdate)
    }

    @Test("fresh devices model carries literal counts and the shared label")
    func devicesFresh() {
        guard case .loaded(let m) = DevicesWidgetModel.make(.loaded(snapshot()), now: scan.addingTimeInterval(720), isScanRunning: false) else { Issue.record("not loaded"); return }
        #expect(m.total == 14 && m.unit == "devices" && !m.isStale)
        #expect(m.ageText == "Scanned 12 minutes ago")
        #expect(m.accessibilityLabel == "14 devices, 9 secure, 2 warning, 1 critical, 2 not probed, scanned 12 minutes ago")
    }

    @Test("one device is singular")
    func singular() {
        let one = StatusCounts(total: 1, secure: 1, warning: 0, critical: 0, notProbed: 0, pending: 0)
        guard case .loaded(let m) = DevicesWidgetModel.make(.loaded(snapshot(one)), now: scan, isScanRunning: false) else { Issue.record("not loaded"); return }
        #expect(m.unit == "device")
    }

    @Test("stale devices model is marked stale and says so in VoiceOver")
    func staleDimsAndSays() {
        guard case .loaded(let m) = DevicesWidgetModel.make(.loaded(snapshot()), now: scan.addingTimeInterval(3600), isScanRunning: true) else { Issue.record("not loaded"); return }
        #expect(m.isStale)
        #expect(m.accessibilityLabel.hasPrefix("Out of date. 14 devices"))
        #expect(m.accessibilityLabel.hasSuffix("scanned 1 hour ago, scan running"))
    }

    @Test("scan now fresh: ring drains, minutes label, literal subnet")
    func scanNowFresh() {
        guard case .loaded(let m) = ScanNowWidgetModel.make(.loaded(snapshot()), now: scan.addingTimeInterval(720), isScanRunning: false) else { Issue.record("not loaded"); return }
        #expect(abs(m.ringFraction - 0.8) < 1e-9)
        #expect(m.ringValue == 12 && m.ringUnit == "min")
        #expect(m.title == "Last scan" && m.smallCaption == "devices" && m.mediumCaption == "192.168.1.0/24")
        #expect(m.accessibilityLabel == "Last scan 12 minutes ago, 14 devices, 9 secure, 2 warning, 1 critical, 2 not probed, 192.168.1.0/24")
    }

    @Test("scan now stale: sliver ring, hours, out of date copy")
    func scanNowStaleCopy() {
        guard case .loaded(let m) = ScanNowWidgetModel.make(.loaded(snapshot()), now: scan.addingTimeInterval(3 * 3600 + 5), isScanRunning: false) else { Issue.record("not loaded"); return }
        #expect(m.isStale && m.ringFraction == 0.08)
        #expect(m.ringValue == 3 && m.ringUnit == "hr")
        #expect(m.title == "Out of date" && m.smallCaption == "may differ" && m.mediumCaption == "Network may have changed")
        #expect(m.accessibilityLabel == "Out of date, scanned 3 hours ago, 14 devices, 9 secure, 2 warning, 1 critical, 2 not probed, may differ")
    }

    @Test("ring age units", arguments: [(0.0, 0, "min"), (59, 0, "min"), (60, 1, "min"), (720, 12, "min"), (3600, 1, "hr"), (86_399, 23, "hr"), (172_800, 2, "d")])
    func ringAge(seconds: Double, value: Int, unit: String) {
        let r = SnapshotFormatting.ringAge(since: scan, now: scan.addingTimeInterval(seconds))
        #expect(r.value == value && r.unit == unit)
    }

    @Test("nil subnet is omitted from VoiceOver and shown as unknown")
    func nilSubnet() {
        guard case .loaded(let m) = ScanNowWidgetModel.make(.loaded(snapshot(subnet: nil)), now: scan, isScanRunning: false) else { Issue.record("not loaded"); return }
        #expect(m.mediumCaption == "Subnet unknown")
        #expect(m.accessibilityLabel == "Last scan just now, 14 devices, 9 secure, 2 warning, 1 critical, 2 not probed")
    }

    func devicesModel(_ typeCounts: [String: Int], now: Date? = nil, running: Bool = false) -> DevicesWidgetModel? {
        var s = snapshot()
        s.typeCounts = typeCounts
        guard case .loaded(let m) = DevicesWidgetModel.make(.loaded(s), now: now ?? scan, isScanRunning: running) else { return nil }
        return m
    }

    func types(_ n: Int) -> [String: Int] {
        Dictionary(uniqueKeysWithValues: (0..<n).map { ("Type \(String(format: "%02d", $0))", n - $0) })
    }

    @Test("rows sort by count descending then label, with the bar scaled to the largest count")
    func typeOrderAndScale() {
        let b = TypeBreakdown.make(["TV": 2, "Computer": 2, "Smart Home": 4, "Camera": 3, "NAS": 1])
        #expect(b.rows.map(\.label) == ["Smart Home", "Camera", "Computer", "TV", "NAS"])
        #expect(b.rows.map(\.count) == [4, 3, 2, 2, 1])
        #expect(b.rows.map(\.fraction) == [1.0, 0.75, 0.5, 0.5, 0.25])
        #expect(b.rows.first?.symbol == "lightbulb")
    }

    @Test("six types stay normal in one column, seven to twelve go compact in two columns", arguments: [(1, TypeDensity.normal, 1), (6, .normal, 1), (7, .compact, 2), (12, .compact, 2)])
    func density(n: Int, density: TypeDensity, columns: Int) {
        let b = TypeBreakdown.make(types(n))
        #expect(b.rows.count == n && b.density == density && b.columns.count == columns)
        #expect(b.columns.flatMap { $0 } == b.rows)
        #expect(b.columns.allSatisfy { $0.count <= 6 })
        #expect(!b.rows.contains { $0.isOther })
    }

    @Test("thirteen or more types show the eleven largest and one Other row that keeps the sum")
    func otherRollUp() {
        for n in [13, 14, 20] {
            let counts = types(n)
            let b = TypeBreakdown.make(counts)
            #expect(b.rows.count == 12 && b.density == .compact)
            #expect(b.rows.last?.isOther == true && b.rows.last?.label == "Other")
            #expect(b.rows.last?.count == counts.values.sorted(by: >).dropFirst(11).reduce(0, +))
            #expect(b.rows.dropLast().map(\.label) == (0..<11).map { "Type \(String(format: "%02d", $0))" })
            #expect(b.rows.map(\.count).reduce(0, +) == counts.values.reduce(0, +))
            #expect(b.columns.flatMap { $0 } == b.rows)
        }
    }

    @Test("an Other row bigger than the largest type still scales within the bars")
    func otherScale() {
        var counts = (0..<12).reduce(into: [String: Int]()) { $0["T\(String(format: "%02d", $1))"] = 2 }
        counts["Extra A"] = 1; counts["Extra B"] = 1; counts["Extra C"] = 1
        let b = TypeBreakdown.make(counts)
        #expect(b.rows.last?.count == 5 && b.rows.last?.fraction == 1.0)
        #expect(b.rows.allSatisfy { $0.fraction > 0 && $0.fraction <= 1 })
    }

    @Test("empty or non-positive type counts mean no chart and a plain line")
    func emptyTypes() {
        for counts in [[:], ["Camera": 0, "TV": -2]] as [[String: Int]] {
            let b = TypeBreakdown.make(counts)
            #expect(b.isEmpty && b.rows.isEmpty && b.columns.isEmpty)
        }
        #expect(WidgetCopy.noTypeData == "No type data")
        #expect(WidgetCopy.byDeviceType == "By device type")
    }

    @Test("symbols come from one table and unknown labels fall back to a question mark")
    func symbols() {
        #expect(TypeSymbol.symbol(for: "Camera") == "video")
        #expect(TypeSymbol.symbol(for: "Router") == "wifi.router")
        #expect(TypeSymbol.symbol(for: "Unknown") == "questionmark.circle")
        #expect(TypeSymbol.symbol(for: "Hovercraft") == "questionmark")
        #expect(TypeSymbol.symbol(for: "Other") == "ellipsis.circle")
    }

    @Test("display names pluralize only the countable types and only when the count is not one")
    func displayNames() {
        let b = TypeBreakdown.make(["Camera": 3, "TV": 1, "Smart Home": 2, "NAS": 1])
        #expect(b.rows.map(\.name) == ["Cameras", "Smart Home", "NAS", "TV"])
    }

    @Test("the model carries the breakdown and its counts add up to the device total")
    func modelBreakdown() {
        let m = devicesModel(["Smart Home": 4, "Camera": 3, "TV": 2, "Computer": 2, "NAS": 1, "Unknown": 2])
        #expect(m?.types.rows.count == 6 && m?.types.density == .normal)
        #expect(m?.types.rows.map(\.count).reduce(0, +) == m?.total)
        #expect(devicesModel([:])?.types.isEmpty == true)
    }

    @Test("medium VoiceOver label is count, subnet, status counts, age, then the type breakdown")
    func mediumLabel() {
        let m = devicesModel(["Smart Home": 4, "Camera": 3, "TV": 1], now: scan.addingTimeInterval(720))
        #expect(m?.mediumAccessibilityLabel == "14 devices, 192.168.1.0/24, 9 secure, 2 warning, 1 critical, 2 not probed, scanned 12 minutes ago. By device type: 4 smart home, 3 cameras, 1 TV")
        let none = devicesModel([:], running: true)
        #expect(none?.mediumAccessibilityLabel == "14 devices, 192.168.1.0/24, 9 secure, 2 warning, 1 critical, 2 not probed, scanned just now. No type data, scan running")
        let stale = devicesModel(["TV": 2], now: scan.addingTimeInterval(3 * 3600))
        #expect(stale?.mediumAccessibilityLabel.hasPrefix("Out of date. 14 devices, 192.168.1.0/24") == true)
        #expect(stale?.isStale == true)
    }

    @Test("a missing subnet is left out of the medium label")
    func mediumLabelNoSubnet() {
        var s = snapshot(subnet: nil)
        s.typeCounts = ["TV": 2]
        guard case .loaded(let m) = DevicesWidgetModel.make(.loaded(s), now: scan, isScanRunning: false) else { Issue.record("not loaded"); return }
        #expect(m.mediumAccessibilityLabel.hasPrefix("14 devices, 9 secure"))
    }

    @Test("the small widget label is unchanged")
    func smallLabelUnchanged() {
        #expect(devicesModel(["TV": 2])?.accessibilityLabel == "14 devices, 9 secure, 2 warning, 1 critical, 2 not probed, scanned just now")
    }
}
