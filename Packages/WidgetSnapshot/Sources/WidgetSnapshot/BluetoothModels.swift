import Foundation

extension WidgetCopy {
    public static let bluetoothSymbol = "wave.3.right"
    public static let nearby = "nearby"
    public static let notAssessed = "not assessed"
    public static let bluetoothOutOfDate = "Bluetooth out of date"
    public static func bluetoothUnit(_ n: Int) -> String { n == 1 ? "Bluetooth device" : "Bluetooth devices" }
    public static func suggested(_ n: Int) -> String { "\(n) suggested?" }
}

/// The Bluetooth line every widget draws, decided apart from the views. Nil means draw nothing and say nothing.
public struct BluetoothIndicatorModel: Equatable, Sendable {
    public var nearby: Int
    public var suggested: Int
    public var isStale: Bool
    /// SnapshotFormatting.shortAge, e.g. "12 min ago".
    public var ageText: String
    /// "7" fresh, "7 · 3 hr ago" stale.
    public var pillText: String
    /// "7 nearby · 2 suggested? · 12 min ago", with the suggested part omitted when 0.
    public var lineText: String
    /// "7 nearby · not assessed · 12 min ago".
    public var securityLineText: String
    public var accessibilityClause: String

    /// The clause the Security shapes speak; Bluetooth devices are never security assessed.
    public var securityAccessibilityClause: String { accessibilityClause + ", not security assessed" }

    /// The line without the age, for the first step of the view's fitting ladder.
    public var lineTextWithoutAge: String { Self.join(nearbyPart, suggestedPart) }
    /// The count and the suggested part with "nearby" dropped, so the suggestion outlasts the age; "7 nearby" when none.
    public var lineTextCompact: String { suggestedPart.map { Self.join("\(nearby)", $0) } ?? nearbyPart }
    /// The line without the suggested part, the last text step before the pill.
    public var lineTextNearbyAndAge: String { Self.join(nearbyPart, ageText) }
    /// The Security line without the age, so "not assessed" outlasts the age in a narrow column.
    public var securityLineTextWithoutAge: String { Self.join(nearbyPart, WidgetCopy.notAssessed) }
    /// The shortest Security line that still says "not assessed".
    public var securityLineTextCompact: String { Self.join("\(nearby)", WidgetCopy.notAssessed) }
    /// The pill text without the age, for a header too narrow for the stale pill.
    public var pillCountText: String { "\(nearby)" }

    var nearbyPart: String { "\(nearby) \(WidgetCopy.nearby)" }
    var suggestedPart: String? { suggested > 0 ? WidgetCopy.suggested(suggested) : nil }

    static func join(_ parts: String?...) -> String {
        parts.compactMap { $0 }.joined(separator: WidgetCopy.captionSeparator)
    }

    public static func make(_ summary: BluetoothSummary?, now: Date) -> BluetoothIndicatorModel? {
        guard let summary, summary.nearby > 0 else { return nil }
        let elapsed = now.timeIntervalSince(summary.scannedAt)
        guard elapsed < Staleness.bluetoothOmitAfter else { return nil }
        let stale = elapsed >= Staleness.bluetoothFreshWindow
        let age = SnapshotFormatting.shortAge(since: summary.scannedAt, now: now)
        let n = summary.nearby, s = summary.suggested
        let nearbyPart = "\(n) \(WidgetCopy.nearby)"
        let suggestedSpoken = s == 0 ? "none suggested"
            : s == 1 ? "1 suggested as a network device, inferred"
            : "\(s) suggested as network devices, inferred"
        let clause = (stale ? WidgetCopy.bluetoothOutOfDate + ", " : "")
            + "\(n) \(WidgetCopy.bluetoothUnit(n)) \(WidgetCopy.nearby), \(suggestedSpoken), Bluetooth scanned "
            + SnapshotFormatting.age(since: summary.scannedAt, now: now)
        return BluetoothIndicatorModel(
            nearby: n, suggested: s, isStale: stale, ageText: age,
            pillText: stale ? "\(n)" + WidgetCopy.captionSeparator + age : "\(n)",
            lineText: join(nearbyPart, s > 0 ? WidgetCopy.suggested(s) : nil, age),
            securityLineText: join(nearbyPart, WidgetCopy.notAssessed, age),
            accessibilityClause: clause)
    }
}
