import Testing
import Foundation
@testable import WidgetSnapshot

@Suite("Widget timeline plan")
struct WidgetTimelinePlanTests {
    let scan = Date(timeIntervalSince1970: 1_000_000)

    @Test("fresh: one entry per minute to the fresh edge, then hourly to 24 h, reload at 24 h")
    func freshPlan() {
        let plan = WidgetTimelinePlan.make(scannedAt: scan, now: scan.addingTimeInterval(90), awaitingUntil: nil)
        let dates = plan.entries.map(\.date)
        #expect(dates.first == scan.addingTimeInterval(90))
        #expect(dates.contains(scan.addingTimeInterval(120)))
        #expect(dates.contains(scan.addingTimeInterval(3600)))
        #expect(dates.contains(scan.addingTimeInterval(7200)))
        #expect(dates.last == scan.addingTimeInterval(23 * 3600))
        #expect(plan.reloadAfter == scan.addingTimeInterval(86_400))
        #expect(dates == dates.sorted() && Set(dates).count == dates.count)
        #expect(plan.entries.allSatisfy { !$0.isScanRunning })
    }

    @Test("over 24 h: entries every 6 h for a day and a reload at the last one")
    func oldPlan() {
        let now = scan.addingTimeInterval(3 * 86_400 + 17)
        let plan = WidgetTimelinePlan.make(scannedAt: scan, now: now, awaitingUntil: nil)
        let days = (4...6).map { scan.addingTimeInterval(Double($0) * 86_400) }
        #expect(plan.entries.map(\.date) == [now] + days)
        #expect(plan.reloadAfter == days.last)
    }

    @Test("missing snapshot: a now entry and a 6 h fallback reload")
    func missingPlan() {
        let now = scan
        let plan = WidgetTimelinePlan.make(scannedAt: nil, now: now, awaitingUntil: nil)
        #expect(plan.entries == [.init(date: now, isScanRunning: false)])
        #expect(plan.reloadAfter == now.addingTimeInterval(21_600))
    }

    @Test("running entries cover now until the timeout, then a not running entry at the timeout")
    func runningEntriesEndAtTimeout() {
        let now = scan.addingTimeInterval(600)
        let until = now.addingTimeInterval(100)
        let plan = WidgetTimelinePlan.make(scannedAt: scan, now: now, awaitingUntil: until)
        #expect(plan.entries.first == .init(date: now, isScanRunning: true))
        #expect(plan.entries.filter(\.isScanRunning).allSatisfy { $0.date < until })
        #expect(plan.entries.contains(.init(date: until, isScanRunning: false)))
        #expect(plan.entries.filter { $0.date >= until }.allSatisfy { !$0.isScanRunning })
    }

    @Test("every plan starts at now and reloads in the future", arguments: [nil, 0.0, 1800, 3599, 3600, 86_399, 86_400, 400_000])
    func alwaysHasNowEntryAndFutureReload(age: Double?) {
        let now = scan.addingTimeInterval(500_000)
        let plan = WidgetTimelinePlan.make(scannedAt: age.map { now.addingTimeInterval(-$0) }, now: now, awaitingUntil: nil)
        #expect(plan.entries.first?.date == now)
        #expect(plan.reloadAfter > now)
        #expect(plan.entries.count <= 90)
    }

    @Test("a scan dated in the future plans as fresh from now")
    func futureScan() {
        let plan = WidgetTimelinePlan.make(scannedAt: scan.addingTimeInterval(60), now: scan, awaitingUntil: nil)
        #expect(plan.entries.first?.date == scan)
        #expect(plan.reloadAfter == scan.addingTimeInterval(60 + 86_400))
    }
}
