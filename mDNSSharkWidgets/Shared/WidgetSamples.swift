import Foundation
import WidgetSnapshot

/// Mockup values for previews and the placeholder only; never written anywhere.
enum WidgetSamples {
    static let counts = StatusCounts(total: 14, secure: 9, warning: 2, critical: 1, notProbed: 2, pending: 0)

    static let sixTypes = ["Smart Home": 4, "Camera": 3, "TV": 2, "Computer": 2, "NAS": 1, "Unknown": 2]
    static let tenTypeCounts = ["Smart Home": 3, "Camera": 2, "TV": 2, "Computer": 1, "NAS": 1, "Unknown": 1, "Router": 1,
                                "Printer": 1, "Audio": 1, "Other Apple": 1]
    /// Fourteen labels, past the twelve-row limit, so the Other roll-up shows.
    static let fourteenTypeCounts = ["Smart Home": 4, "Camera": 3, "TV": 2, "Computer": 1, "NAS": 1, "Unknown": 1, "Router": 1,
                                     "Printer": 1, "Audio": 1, "Other Apple": 1, "Doorbell": 1, "Thermostat": 1, "Lock": 1,
                                     "Sensor": 1]

    static func snapshot(scannedAt: Date, typeCounts: [String: Int] = sixTypes) -> WidgetSnapshot {
        let total = typeCounts.values.reduce(0, +)
        var counts = counts
        counts.total = total
        counts.secure = total - 5
        return WidgetSnapshot(version: WidgetSnapshot.schemaVersion, scannedAt: scannedAt, subnet: "192.168.1.0/24",
                              counts: counts, typeCounts: typeCounts, history: [], newDevices: [], topology: [],
                              topologyOverflow: 0, ownDeviceKey: nil)
    }

    private static func entry(ago: TimeInterval, types: [String: Int] = sixTypes, running: Bool = false) -> SnapshotEntry {
        let now = Date()
        return SnapshotEntry(date: now, result: .loaded(snapshot(scannedAt: now.addingTimeInterval(-ago), typeCounts: types)),
                             isScanRunning: running)
    }

    static var fresh: SnapshotEntry { entry(ago: 720) }
    static var tenTypes: SnapshotEntry { entry(ago: 720, types: tenTypeCounts) }
    static var fourteenTypes: SnapshotEntry { entry(ago: 720, types: fourteenTypeCounts) }
    static var stale: SnapshotEntry { entry(ago: 3 * 3600) }
    static var staleFourteenTypes: SnapshotEntry { entry(ago: 3 * 3600, types: fourteenTypeCounts) }
    static var running: SnapshotEntry { entry(ago: 720, running: true) }

    static var empty: SnapshotEntry { SnapshotEntry(date: Date(), result: .missing, isScanRunning: false) }
}
