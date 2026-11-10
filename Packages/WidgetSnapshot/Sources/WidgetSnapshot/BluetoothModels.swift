import Foundation

extension WidgetCopy {
    public static let bluetoothSymbol = "wave.3.right"
    public static let nearby = "nearby"
    public static let notAssessed = "not assessed"
    public static let bluetoothOutOfDate = "Bluetooth out of date"
    public static func bluetoothUnit(_ n: Int) -> String { n == 1 ? "Bluetooth device" : "Bluetooth devices" }
}

/// The Bluetooth line every widget draws, decided apart from the views. Nil means draw nothing and say nothing.
public struct BluetoothIndicatorModel: Equatable, Sendable {
    public var nearby: Int
    public var isStale: Bool
    /// SnapshotFormatting.shortAge, e.g. "12 min ago".
    public var ageText: String
    /// "7" fresh, "7 · 3 hr ago" stale; "7 · 30+ min ago" from the stale edge to the hour.
    public var pillText: String
    /// "7 nearby · 12 min ago".
    public var lineText: String
    /// "7 nearby · not assessed · 12 min ago".
    public var securityLineText: String
    public var accessibilityClause: String

    /// The clause the Security shapes speak; Bluetooth devices are never security assessed.
    public var securityAccessibilityClause: String { accessibilityClause + ", not security assessed" }

    /// The line without the age, the last text step before the pill.
    public var lineTextWithoutAge: String { nearbyPart }
    /// The Security line without the age, so "not assessed" outlasts the age in a narrow column.
    public var securityLineTextWithoutAge: String { Self.join(nearbyPart, WidgetCopy.notAssessed) }
    /// The shortest Security line that still says "not assessed".
    public var securityLineTextCompact: String { Self.join("\(nearby)", WidgetCopy.notAssessed) }
    /// The pill text without the age, for a header too narrow for the stale pill.
    public var pillCountText: String { "\(nearby)" }

    var nearbyPart: String { "\(nearby) \(WidgetCopy.nearby)" }

    static func join(_ parts: String?...) -> String {
        parts.compactMap { $0 }.joined(separator: WidgetCopy.captionSeparator)
    }

    public static func make(_ summary: BluetoothSummary?, now: Date) -> BluetoothIndicatorModel? {
        guard let summary, summary.nearby > 0 else { return nil }
        let elapsed = now.timeIntervalSince(summary.scannedAt)
        guard elapsed < Staleness.bluetoothOmitAfter else { return nil }
        let stale = elapsed >= Staleness.bluetoothFreshWindow
        // The timeline has no Bluetooth marks between the stale edge and the hour, so a minute count there would
        // sit under-reported for up to 30 minutes; "30+" is true for the whole window.
        let beforeTheHour = stale && elapsed < 3600
        let age = beforeTheHour ? "30+ min ago" : SnapshotFormatting.shortAge(since: summary.scannedAt, now: now)
        let spokenAge = beforeTheHour ? "over 30 minutes ago" : SnapshotFormatting.age(since: summary.scannedAt, now: now)
        let n = summary.nearby
        let nearbyPart = "\(n) \(WidgetCopy.nearby)"
        let clause = (stale ? WidgetCopy.bluetoothOutOfDate + ", " : "")
            + "\(n) \(WidgetCopy.bluetoothUnit(n)) \(WidgetCopy.nearby), Bluetooth scanned " + spokenAge
        return BluetoothIndicatorModel(
            nearby: n, isStale: stale, ageText: age,
            pillText: stale ? "\(n)" + WidgetCopy.captionSeparator + age : "\(n)",
            lineText: join(nearbyPart, age),
            securityLineText: join(nearbyPart, WidgetCopy.notAssessed, age),
            accessibilityClause: clause)
    }
}
