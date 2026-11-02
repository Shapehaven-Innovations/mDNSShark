import Foundation

extension WidgetCopy {
    public static let security = "Security"
    public static let allClear = "All clear"
    public static let notProbedTitle = "Not probed"
    public static let noDevices = "No devices"
    public static let issuesPerScan = "Issues per scan"
    public static let critical = "Critical"
    public static let warning = "Warning"
    public static let secure = "Secure"
    public static let latest = "Latest"
    public static let noHistory = "No scan history yet"

    public static let scanned = "Scanned"
    public static let captionSeparator = " · "

    public static func checking(_ n: Int) -> String { "\(n) checking" }
    public static func issueUnit(_ n: Int) -> String { n == 1 ? "issue" : "issues" }
    public static func notProbedCount(_ n: Int) -> String { "\(n) not probed" }
}

/// The headline state of the Security widget; pending and not probed never count as secure.
public enum SecurityVerdict: Equatable, Sendable {
    case noDevices
    case issues(Int)
    case checking(pending: Int)
    case allClear
    case nothingProbed
}

extension StatusCounts {
    public var securityVerdict: SecurityVerdict {
        if total == 0 { return .noDevices }
        if issues > 0 { return .issues(issues) }
        if pending > 0 { return .checking(pending: pending) }
        if secure > 0 { return .allClear }
        return .nothingProbed
    }

    /// The first nonzero of critical, warning, pending, secure and not probed.
    public var worstKind: StatusKind? {
        [StatusKind.critical, .warning, .pending, .secure, .notProbed].first { count(of: $0) > 0 }
    }

    /// Secure through not probed with zeros kept, then pending only when above zero.
    public var legend: [CapsuleSegment] {
        var items = [StatusKind.secure, .warning, .critical, .notProbed].map { CapsuleSegment(kind: $0, count: count(of: $0)) }
        if pending > 0 { items.append(CapsuleSegment(kind: .pending, count: pending)) }
        return items
    }
}

public enum SecurityHero: Equatable, Sendable {
    case count(Int, unit: String)
    case title(String)
}

extension SecurityVerdict {
    var hero: SecurityHero {
        switch self {
        case .issues(let n): .count(n, unit: WidgetCopy.issueUnit(n))
        case .checking: .count(0, unit: WidgetCopy.issueUnit(0))
        case .allClear: .title(WidgetCopy.allClear)
        case .nothingProbed: .title(WidgetCopy.notProbedTitle)
        case .noDevices: .title(WidgetCopy.noDevices)
        }
    }

    /// The accessory state symbol; stale wins over every verdict.
    func stateSymbol(isStale: Bool) -> String {
        if isStale { return "clock" }
        switch self {
        case .issues: return "exclamationmark.shield"
        case .allClear: return "checkmark.shield"
        case .checking: return "hourglass"
        case .nothingProbed, .noDevices: return "questionmark.circle"
        }
    }
}

/// The home screen Security widget (small, medium, large), decided apart from the views.
public struct SecurityWidgetModel: Equatable, Sendable {
    public var verdict: SecurityVerdict
    public var hero: SecurityHero
    public var headerSymbol: StatusKind?
    public var segments: [CapsuleSegment]
    /// Secure, warning, critical and not probed with zeros kept, for the medium 2x2 grid.
    public var grid: [CapsuleSegment]
    public var legend: [CapsuleSegment]
    public var checkingNote: String?
    public var smallCaption: String
    public var ageText: String
    public var largeCaption: String
    public var chart: IssueChart
    public var isStale: Bool
    public var isScanRunning: Bool
    public var accessibilityLabel: String
    /// The large widget's label: the shared label, then the chart's spoken list, then the running suffix.
    public var largeAccessibilityLabel: String

    public static func make(_ result: SnapshotDecodeResult<WidgetSnapshot>, now: Date,
                            isScanRunning: Bool) -> WidgetContentState<SecurityWidgetModel> {
        .from(result) { s in
            let counts = s.counts, verdict = counts.securityVerdict
            let stale = !Staleness.isFresh(scannedAt: s.scannedAt, now: now)
            let age = SnapshotFormatting.shortAge(since: s.scannedAt, now: now)
            let ageText = WidgetCopy.scanned + " " + age
            let notProbed = WidgetCopy.notProbedCount(counts.notProbed)
            let base = SnapshotFormatting.securityAccessibilityLabel(counts: counts, scannedAt: s.scannedAt, now: now,
                                                                     isStale: stale, isScanRunning: false)
            let running = isScanRunning ? WidgetCopy.scanRunningSuffix : ""
            let label = base + running
            let chart = IssueChart.make(s.history)
            return SecurityWidgetModel(
                verdict: verdict, hero: verdict.hero, headerSymbol: counts.worstKind, segments: counts.capsuleSegments,
                grid: Array(counts.legend.prefix(4)), legend: counts.legend,
                checkingNote: counts.pending > 0 ? WidgetCopy.checking(counts.pending) : nil,
                smallCaption: notProbed + WidgetCopy.captionSeparator + age, ageText: ageText,
                largeCaption: notProbed + WidgetCopy.captionSeparator + ageText, chart: chart,
                isStale: stale, isScanRunning: isScanRunning, accessibilityLabel: label,
                largeAccessibilityLabel: base + ". " + chart.accessibilityLabel + running)
        }
    }
}

/// The lock screen Security shapes (circular, rectangular, inline); they carry status by symbol and position only.
public struct SecurityAccessoryModel: Equatable, Sendable {
    /// Secure over probed (secure, warning, critical, pending), or 0 when nothing was probed.
    public var gaugeFraction: Double
    public var gaugeValue: Int
    public var stateSymbol: String
    public var primaryRow: [CapsuleSegment]
    public var secondaryRow: [CapsuleSegment]
    public var rectTitle: String
    public var inlineText: String
    public var inlineSymbol: String
    public var isStale: Bool
    public var accessibilityLabel: String

    public static func make(_ result: SnapshotDecodeResult<WidgetSnapshot>, now: Date,
                            isScanRunning: Bool) -> WidgetContentState<SecurityAccessoryModel> {
        .from(result) { s in
            let counts = s.counts, verdict = counts.securityVerdict
            let stale = !Staleness.isFresh(scannedAt: s.scannedAt, now: now)
            let probed = counts.secure + counts.issues + counts.pending
            var secondary = [CapsuleSegment(kind: .secure, count: counts.secure), CapsuleSegment(kind: .notProbed, count: counts.notProbed)]
            if counts.pending > 0 { secondary.append(CapsuleSegment(kind: .pending, count: counts.pending)) }
            let symbol = verdict.stateSymbol(isStale: stale)
            return SecurityAccessoryModel(
                gaugeFraction: probed > 0 ? Double(counts.secure) / Double(probed) : 0, gaugeValue: counts.issues,
                stateSymbol: symbol,
                primaryRow: [CapsuleSegment(kind: .critical, count: counts.critical), CapsuleSegment(kind: .warning, count: counts.warning)],
                secondaryRow: secondary, rectTitle: stale ? WidgetCopy.outOfDate : WidgetCopy.security,
                inlineText: inlineText(counts, stale: stale), inlineSymbol: symbol, isStale: stale,
                accessibilityLabel: SnapshotFormatting.securityAccessibilityLabel(
                    counts: counts, scannedAt: s.scannedAt, now: now, isStale: stale, isScanRunning: isScanRunning))
        }
    }

    /// Stale never says All clear; fresh always states the not probed count when there is one to state.
    static func inlineText(_ counts: StatusCounts, stale: Bool) -> String {
        if stale { return WidgetCopy.outOfDate + ", " + SnapshotFormatting.issuePhrase(counts.issues) }
        let notProbed = WidgetCopy.notProbedCount(counts.notProbed)
        switch counts.securityVerdict {
        case .issues(let n): return SnapshotFormatting.issuePhrase(n) + ", " + notProbed
        case .allClear: return WidgetCopy.allClear + ", " + notProbed
        case .checking(let p): return SnapshotFormatting.issuePhrase(0) + ", " + WidgetCopy.checking(p)
        case .nothingProbed: return WidgetCopy.notProbedTitle + ", \(counts.total) " + WidgetCopy.deviceUnit(counts.total)
        case .noDevices: return WidgetCopy.noDevices
        }
    }
}
