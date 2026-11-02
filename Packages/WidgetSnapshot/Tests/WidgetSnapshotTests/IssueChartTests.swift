import Testing
import Foundation
@testable import WidgetSnapshot

@Suite("Issue chart")
struct IssueChartTests {
    let t = Date(timeIntervalSince1970: 4_000_000)
    func h(_ pairs: [(Int, Int)]) -> [ScanSample] {   // (critical, warning), oldest first
        pairs.enumerated().map { i, p in
            ScanSample(at: t.addingTimeInterval(Double(i) * 600),
                       counts: StatusCounts(total: 20, secure: 20 - p.0 - p.1, warning: p.1, critical: p.0, notProbed: 0, pending: 0))
        }
    }
    let mockup: [(Int, Int)] = [(0, 1), (0, 1), (1, 1), (1, 2), (0, 2), (0, 2), (0, 1), (1, 1), (1, 2), (1, 2), (1, 2), (1, 2)]

    @Test("mockup history: 12 slots, axis 0 to 3, literal stacks")
    func mockupChart() {
        let chart = IssueChart.make(h(mockup))
        #expect(chart.slots.count == 12 && chart.slots.allSatisfy { $0 != nil })
        #expect(chart.yMax == 3 && chart.ticks == [0, 1, 2, 3])
        #expect(chart.slots.map { $0!.total } == [1, 1, 2, 3, 2, 2, 1, 2, 3, 3, 3, 3])
        #expect(chart.slots[3]!.critical == 1 && chart.slots[3]!.warning == 2)
        #expect(abs(chart.slots[3]!.criticalFraction - 1.0 / 3) < 1e-9 && abs(chart.slots[3]!.warningFraction - 2.0 / 3) < 1e-9)
        #expect(chart.leftLabel == "11 scans ago" && chart.rightLabel == "Latest" && chart.note == nil)
    }

    @Test("ceiling steps along the ladder and never fits the data", arguments: [(0, 3), (1, 3), (3, 3), (4, 6), (7, 12), (13, 30), (31, 60), (601, 900), (1000, 1200)])
    func ceiling(maxIssues: Int, expected: Int) {
        #expect(IssueChart.ceiling(for: maxIssues) == expected)
    }

    @Test("ticks are integer thirds of the ceiling")
    func ticks() {
        #expect(IssueChart.make(h([(10, 30)])).ticks == [0, 20, 40, 60])
    }

    @Test("few samples fill from the right with a note")
    func fewSamples() {
        let chart = IssueChart.make(h([(1, 2)]))
        #expect(chart.slots.prefix(11).allSatisfy { $0 == nil } && chart.slots[11]?.total == 3)
        #expect(chart.leftLabel == nil && chart.note == "1 of 12 scans so far")
        #expect(IssueChart.make(h([(0, 1), (1, 2)])).leftLabel == "1 scan ago")
    }

    @Test("all-zero history keeps the floor axis and says so")
    func allZero() {
        let chart = IssueChart.make(h(Array(repeating: (0, 0), count: 5)))
        #expect(chart.yMax == 3 && chart.slots.compactMap { $0 }.allSatisfy { $0.total == 0 })
        #expect(chart.note == "No issues in the last 5 scans")
    }

    @Test("empty history has no bars and the no-history note")
    func empty() {
        let chart = IssueChart.make([])
        #expect(chart.slots.allSatisfy { $0 == nil } && chart.note == WidgetCopy.noHistory && chart.sampleCount == 0)
    }

    @Test("more than 12 samples keep the newest 12")
    func keepsNewest() {
        let chart = IssueChart.make(h(Array(repeating: (0, 0), count: 3) + mockup))
        #expect(chart.slots.map { $0!.total } == [1, 1, 2, 3, 2, 2, 1, 2, 3, 3, 3, 3])
    }

    @Test("VoiceOver lists every scan oldest to latest and the latest split")
    func spoken() {
        #expect(IssueChart.make(h(mockup)).accessibilityLabel ==
                "Issues per scan, oldest to latest: 1, 1, 2, 3, 2, 2, 1, 2, 3, 3, 3, 3. Latest scan 3 issues: 1 critical, 2 warning")
        #expect(IssueChart.make(h([(0, 0)])).accessibilityLabel == "Issues per scan: 1 of 12 scans so far. Latest scan 0 issues")
        #expect(IssueChart.make([]).accessibilityLabel == WidgetCopy.noHistory)
    }
}
