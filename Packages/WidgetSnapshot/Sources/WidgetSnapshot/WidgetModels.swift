import Foundation

/// Every user-facing string the widget views show, kept here so the copy is tested with the models.
public enum WidgetCopy {
    public static let noScan = "No scan yet"
    public static let updateApp = "Update mDNSShark"
    public static let outOfDate = "Out of date"
    public static let lastScan = "Last scan"
    public static let byDeviceType = "By device type"
    public static let noTypeData = "No type data"
    public static let mayDiffer = "may differ"
    public static let networkMayHaveChanged = "Network may have changed"
    public static let subnetUnknown = "Subnet unknown"
    public static let devices = "devices"
    public static let scan = "Scan"
    public static let scanAccessibilityLabel = "Scan now, opens mDNSShark"
    public static let emptyAccessibilityLabel = noScan
    public static let needsUpdateAccessibilityLabel = "Update mDNSShark to show this widget"
    public static let scanRunningSuffix = ", scan running"

    public static let scanBackgroundAccessibilityLabel = "Scan now"

    /// VoiceOver label for the Scan button: only the open-the-app path says it opens the app.
    public static func scanButtonLabel(background: Bool, isRunning: Bool) -> String {
        (background ? scanBackgroundAccessibilityLabel : scanAccessibilityLabel) + (isRunning ? scanRunningSuffix : "")
    }

    public static func deviceUnit(_ count: Int) -> String { count == 1 ? "device" : "devices" }
}

public enum StatusKind: String, CaseIterable, Sendable {
    case secure, warning, critical, notProbed, pending

    public var symbol: String {
        switch self {
        case .secure: "checkmark.shield.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .critical: "xmark.shield.fill"
        case .notProbed: "questionmark.circle"
        case .pending: "hourglass"
        }
    }

    /// Not probed and pending are drawn as outlines so they never read as a status fill.
    public var isOutlined: Bool { self == .notProbed || self == .pending }
}

public struct CapsuleSegment: Equatable, Sendable {
    public var kind: StatusKind
    public var count: Int

    public init(kind: StatusKind, count: Int) {
        self.kind = kind
        self.count = count
    }
}

extension StatusCounts {
    func count(of kind: StatusKind) -> Int {
        switch kind {
        case .secure: secure
        case .warning: warning
        case .critical: critical
        case .notProbed: notProbed
        case .pending: pending
        }
    }

    /// Status order with zero counts omitted.
    public var capsuleSegments: [CapsuleSegment] {
        StatusKind.allCases.map { CapsuleSegment(kind: $0, count: count(of: $0)) }.filter { $0.count > 0 }
    }
}

public enum WidgetContentState<Content: Equatable & Sendable>: Equatable, Sendable {
    case noScan
    case needsUpdate
    case loaded(Content)

    static func from(_ result: SnapshotDecodeResult<WidgetSnapshot>, _ make: (WidgetSnapshot) -> Content) -> Self {
        switch result {
        case .missing: .noScan
        case .newer: .needsUpdate
        case .loaded(let snapshot): .loaded(make(snapshot))
        }
    }
}

/// The one place a device type label maps to an SF Symbol; labels come from the app's DeviceType.label.
public enum TypeSymbol {
    public static let other = "ellipsis.circle"
    public static let fallback = "questionmark"

    static let table: [String: String] = [
        "Router": "wifi.router", "Other Apple": "laptopcomputer.and.iphone", "Computer": "laptopcomputer",
        "Printer": "printer", "TV": "tv", "Camera": "video", "Audio": "hifispeaker", "Smart Home": "lightbulb",
        "NAS": "externaldrive.connected.to.line.below", "Unknown": "questionmark.circle", "Other": other,
    ]

    public static func symbol(for label: String) -> String { table[label] ?? fallback }
}

/// One ranked bar in the medium Devices widget.
public struct TypeRow: Equatable, Sendable {
    public var label: String
    public var name: String
    public var count: Int
    /// Count over the largest displayed count, so the longest bar is full width.
    public var fraction: Double
    public var symbol: String
    public var isOther: Bool

    static let pluralized: Set<String> = ["Router", "Computer", "Printer", "TV", "Camera"]

    init(label: String, count: Int, maxCount: Int, isOther: Bool = false) {
        self.label = label
        self.name = count != 1 && Self.pluralized.contains(label) ? label + "s" : label
        self.count = count
        self.fraction = maxCount > 0 ? Double(count) / Double(maxCount) : 0
        self.symbol = TypeSymbol.symbol(for: label)
        self.isOther = isOther
    }

    /// Lowercased for speech except all-caps names such as TV and NAS.
    var spokenName: String { name == name.uppercased() ? name : name.lowercased() }
}

public enum TypeDensity: Equatable, Sendable { case normal, compact }

/// Which rows the medium Devices widget draws and how densely, decided apart from the views.
public struct TypeBreakdown: Equatable, Sendable {
    public static let normalLimit = 6
    public static let maxRows = 12
    public static let otherLabel = "Other"

    public var rows: [TypeRow]
    public var density: TypeDensity

    public var isEmpty: Bool { rows.isEmpty }

    /// One column when normal; two columns of up to six when compact.
    public var columns: [[TypeRow]] {
        guard !rows.isEmpty else { return [] }
        guard density == .compact else { return [rows] }
        let split = (rows.count + 1) / 2
        return [Array(rows.prefix(split)), Array(rows.dropFirst(split))]
    }

    /// Count descending then label; past twelve types the eleven largest stay and the rest roll into one Other row.
    public static func make(_ typeCounts: [String: Int]) -> TypeBreakdown {
        let sorted = typeCounts.filter { $0.value > 0 }
            .sorted { $0.value != $1.value ? $0.value > $1.value : $0.key < $1.key }
        var entries = sorted.map { (label: $0.key, count: $0.value, isOther: false) }
        if entries.count > maxRows {
            let rest = entries.dropFirst(maxRows - 1).reduce(0) { $0 + $1.count }
            entries = Array(entries.prefix(maxRows - 1)) + [(otherLabel, rest, true)]
        }
        let maxCount = entries.map(\.count).max() ?? 0
        let rows = entries.map { TypeRow(label: $0.label, count: $0.count, maxCount: maxCount, isOther: $0.isOther) }
        return TypeBreakdown(rows: rows, density: rows.count <= normalLimit ? .normal : .compact)
    }

    var spokenSummary: String {
        guard !rows.isEmpty else { return WidgetCopy.noTypeData }
        return WidgetCopy.byDeviceType + ": " + rows.map { "\($0.count) \($0.spokenName)" }.joined(separator: ", ")
    }
}

public struct DevicesWidgetModel: Equatable, Sendable {
    public var total: Int
    public var unit: String
    public var segments: [CapsuleSegment]
    public var types: TypeBreakdown
    public var ageText: String
    public var isStale: Bool
    public var isScanRunning: Bool
    public var bluetooth: BluetoothIndicatorModel?
    /// The small widget's label.
    public var accessibilityLabel: String
    /// The medium widget's label: count, subnet, status counts, age, then the type breakdown.
    public var mediumAccessibilityLabel: String

    public static func make(_ result: SnapshotDecodeResult<WidgetSnapshot>, now: Date,
                            isScanRunning: Bool) -> WidgetContentState<DevicesWidgetModel> {
        .from(result) { s in
            let stale = !Staleness.isFresh(scannedAt: s.scannedAt, now: now)
            let prefix = stale ? WidgetCopy.outOfDate + ". " : ""
            let bluetooth = BluetoothIndicatorModel.make(s.bluetooth, now: now)
            let suffix = (bluetooth.map { ". " + $0.accessibilityClause } ?? "") + (isScanRunning ? WidgetCopy.scanRunningSuffix : "")
            let label = prefix + SnapshotFormatting.accessibilityLabel(counts: s.counts, scannedAt: s.scannedAt, now: now) + suffix
            let types = TypeBreakdown.make(s.typeCounts)
            var parts = ["\(s.counts.total) \(WidgetCopy.deviceUnit(s.counts.total))"]
            if let subnet = s.subnet { parts.append(subnet) }
            parts += SnapshotFormatting.statusPhrases(s.counts)
            parts.append("scanned " + SnapshotFormatting.age(since: s.scannedAt, now: now))
            let medium = prefix + parts.joined(separator: ", ") + ". " + types.spokenSummary + suffix
            return DevicesWidgetModel(
                total: s.counts.total, unit: WidgetCopy.deviceUnit(s.counts.total),
                segments: s.counts.capsuleSegments, types: types,
                ageText: "Scanned " + SnapshotFormatting.age(since: s.scannedAt, now: now),
                isStale: stale, isScanRunning: isScanRunning, bluetooth: bluetooth,
                accessibilityLabel: label, mediumAccessibilityLabel: medium)
        }
    }
}

public struct ScanNowWidgetModel: Equatable, Sendable {
    public static let staleRingFraction = 0.08

    public var total: Int
    public var subnet: String?
    public var segments: [CapsuleSegment]
    public var ringFraction: Double
    public var ringValue: Int
    public var ringUnit: String
    public var isStale: Bool
    public var title: String
    public var smallCaption: String
    public var mediumCaption: String
    public var isScanRunning: Bool
    public var bluetooth: BluetoothIndicatorModel?
    public var accessibilityLabel: String

    public static func make(_ result: SnapshotDecodeResult<WidgetSnapshot>, now: Date,
                            isScanRunning: Bool) -> WidgetContentState<ScanNowWidgetModel> {
        .from(result) { s in
            let stale = !Staleness.isFresh(scannedAt: s.scannedAt, now: now)
            let age = SnapshotFormatting.age(since: s.scannedAt, now: now)
            let ring = SnapshotFormatting.ringAge(since: s.scannedAt, now: now)
            let devices = "\(s.counts.total) \(WidgetCopy.deviceUnit(s.counts.total))"
            let status = SnapshotFormatting.statusPhrases(s.counts)
            let parts = stale ? ["\(WidgetCopy.outOfDate), scanned \(age)", devices] + status + [WidgetCopy.mayDiffer]
                              : ["\(WidgetCopy.lastScan) \(age)", devices] + status + (s.subnet.map { [$0] } ?? [])
            let bluetooth = BluetoothIndicatorModel.make(s.bluetooth, now: now)
            let label = parts.joined(separator: ", ") + (bluetooth.map { ". " + $0.accessibilityClause } ?? "")
                + (isScanRunning ? WidgetCopy.scanRunningSuffix : "")
            return ScanNowWidgetModel(
                total: s.counts.total, subnet: s.subnet, segments: s.counts.capsuleSegments,
                ringFraction: stale ? staleRingFraction : Staleness.ringFraction(scannedAt: s.scannedAt, now: now),
                ringValue: ring.value, ringUnit: ring.unit, isStale: stale,
                title: stale ? WidgetCopy.outOfDate : WidgetCopy.lastScan,
                smallCaption: stale ? WidgetCopy.mayDiffer : WidgetCopy.deviceUnit(s.counts.total),
                mediumCaption: stale ? WidgetCopy.networkMayHaveChanged : (s.subnet ?? WidgetCopy.subnetUnknown),
                isScanRunning: isScanRunning, bluetooth: bluetooth, accessibilityLabel: label)
        }
    }
}
