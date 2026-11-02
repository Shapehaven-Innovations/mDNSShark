import Foundation

/// One scan's stacked bar; fractions are each literal count over the chart's ceiling.
public struct IssueBar: Equatable, Sendable {
    public var at: Date
    public var critical: Int
    public var warning: Int
    public var total: Int { critical + warning }
    public var criticalFraction: Double
    public var warningFraction: Double
}

/// The large Security widget's "Issues per scan" chart, decided apart from the views.
public struct IssueChart: Equatable, Sendable {
    public static let slotCount = 12
    public static let ladder = [3, 6, 12, 30, 60, 120, 300, 600]

    /// Always 12 slots, oldest first, with nil slots on the left.
    public var slots: [IssueBar?]
    public var yMax: Int
    public var ticks: [Int]
    public var sampleCount: Int
    public var leftLabel: String?
    public var rightLabel: String
    public var note: String?
    public var accessibilityLabel: String

    /// The ceiling steps along the ladder instead of fitting the data, so one warning never fills the plot.
    public static func ceiling(for maxIssues: Int) -> Int {
        ladder.first { $0 >= max(maxIssues, 1) } ?? ((maxIssues + 299) / 300) * 300
    }

    public static func make(_ history: [ScanSample]) -> IssueChart {
        let samples = Array(history.suffix(slotCount))
        let n = samples.count
        let yMax = ceiling(for: samples.map(\.counts.issues).max() ?? 0)
        let bars = samples.map { s in
            IssueBar(at: s.at, critical: s.counts.critical, warning: s.counts.warning,
                     criticalFraction: Double(s.counts.critical) / Double(yMax),
                     warningFraction: Double(s.counts.warning) / Double(yMax))
        }
        let slots: [IssueBar?] = Array(repeating: nil, count: slotCount - n) + bars
        let note: String? = n == 0 ? WidgetCopy.noHistory
            : n < 3 ? "\(n) of \(slotCount) scans so far"
            : bars.allSatisfy({ $0.total == 0 }) ? "No issues in the last \(n) scans" : nil
        return IssueChart(
            slots: slots, yMax: yMax, ticks: [0, yMax / 3, 2 * yMax / 3, yMax], sampleCount: n,
            leftLabel: n < 2 ? nil : "\(n - 1) scan\(n - 1 == 1 ? "" : "s") ago", rightLabel: WidgetCopy.latest,
            note: note, accessibilityLabel: spoken(bars, note: note))
    }

    private static func spoken(_ bars: [IssueBar], note: String?) -> String {
        guard let latest = bars.last else { return WidgetCopy.noHistory }
        var text = bars.count >= 3
            ? WidgetCopy.issuesPerScan + ", oldest to latest: " + bars.map { "\($0.total)" }.joined(separator: ", ")
            : WidgetCopy.issuesPerScan + ": " + (note ?? "")
        text += ". Latest scan " + SnapshotFormatting.issuePhrase(latest.total)
        if latest.total > 0 { text += ": \(latest.critical) critical, \(latest.warning) warning" }
        return text
    }
}
