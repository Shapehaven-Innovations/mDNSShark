import Foundation
import WidgetSnapshot

/// Sample values for previews and the placeholder only; never written anywhere.
enum WidgetSamples {
    static let counts = StatusCounts(total: 14, secure: 9, warning: 2, critical: 1, notProbed: 2, pending: 0)

    static let sixTypes = ["Smart Home": 4, "Camera": 3, "TV": 2, "Computer": 2, "NAS": 1, "Unknown": 2]
    static let tenTypeCounts = ["Smart Home": 3, "Camera": 2, "TV": 2, "Computer": 1, "NAS": 1, "Unknown": 1, "Router": 1,
                                "Printer": 1, "Audio": 1, "Other Apple": 1]
    /// Fourteen labels, past the twelve-row limit, so the Other roll-up shows.
    static let fourteenTypeCounts = ["Smart Home": 4, "Camera": 3, "TV": 2, "Computer": 1, "NAS": 1, "Unknown": 1, "Router": 1,
                                     "Printer": 1, "Audio": 1, "Other Apple": 1, "Doorbell": 1, "Thermostat": 1, "Lock": 1,
                                     "Sensor": 1]

    /// Counts only, dated `ago` seconds before now.
    static func bluetooth(nearby: Int, ago: TimeInterval) -> BluetoothSummary {
        BluetoothSummary(scannedAt: Date().addingTimeInterval(-ago), nearby: nearby)
    }

    static func snapshot(scannedAt: Date, typeCounts: [String: Int] = sixTypes, bluetooth: BluetoothSummary? = nil) -> WidgetSnapshot {
        let total = typeCounts.values.reduce(0, +)
        var counts = counts
        counts.total = total
        counts.secure = total - 5
        return WidgetSnapshot(version: WidgetSnapshot.schemaVersion, scannedAt: scannedAt, subnet: "192.168.1.0/24",
                              counts: counts, typeCounts: typeCounts, history: [], newDevices: [], topology: [],
                              topologyOverflow: 0, ownDeviceKey: nil, bluetooth: bluetooth)
    }

    private static func entry(ago: TimeInterval, types: [String: Int] = sixTypes, running: Bool = false,
                              bluetooth: BluetoothSummary? = nil) -> SnapshotEntry {
        let now = Date()
        return SnapshotEntry(date: now, result: .loaded(snapshot(scannedAt: now.addingTimeInterval(-ago), typeCounts: types,
                                                                 bluetooth: bluetooth)),
                             isScanRunning: running)
    }

    static var fresh: SnapshotEntry { entry(ago: 720) }
    static var tenTypes: SnapshotEntry { entry(ago: 720, types: tenTypeCounts) }
    static var fourteenTypes: SnapshotEntry { entry(ago: 720, types: fourteenTypeCounts) }
    static var stale: SnapshotEntry { entry(ago: 3 * 3600) }
    static var staleFourteenTypes: SnapshotEntry { entry(ago: 3 * 3600, types: fourteenTypeCounts) }
    static var running: SnapshotEntry { entry(ago: 720, running: true) }
    static var freshBluetooth: SnapshotEntry { entry(ago: 720, bluetooth: bluetooth(nearby: 7, ago: 720)) }
    /// LAN fresh, Bluetooth stale.
    static var staleBluetooth: SnapshotEntry { entry(ago: 720, bluetooth: bluetooth(nearby: 7, ago: 3 * 3600)) }
    /// LAN and Bluetooth both stale, the widest pill and caption together.
    static var bothStaleBluetooth: SnapshotEntry {
        entry(ago: 3 * 3600, bluetooth: bluetooth(nearby: 17, ago: 23 * 3600))
    }

    static var empty: SnapshotEntry { SnapshotEntry(date: Date(), result: .missing, isScanRunning: false) }
    static var needsUpdate: SnapshotEntry { SnapshotEntry(date: Date(), result: .newer(version: 2), isScanRunning: false) }

    // MARK: Security

    /// Twelve (critical, warning) pairs, oldest first.
    static let securityHistory = [(0, 1), (0, 1), (1, 1), (1, 2), (0, 2), (0, 2), (0, 1), (1, 1), (1, 2), (1, 2), (1, 2), (1, 2)]
    static let busyHistory = [(2, 6), (3, 9), (1, 4), (5, 14), (4, 12), (8, 20), (6, 18), (10, 30)]

    private static func counts(_ s: Int, _ w: Int, _ c: Int, _ np: Int, _ p: Int) -> StatusCounts {
        StatusCounts(total: s + w + c + np + p, secure: s, warning: w, critical: c, notProbed: np, pending: p)
    }

    /// Ten minutes between scans, the newest at the snapshot's scan time.
    private static func history(_ pairs: [(Int, Int)], endingAt end: Date) -> [ScanSample] {
        pairs.enumerated().map { i, p in
            ScanSample(at: end.addingTimeInterval(Double(i - pairs.count + 1) * 600),
                       counts: StatusCounts(total: 14, secure: 14 - p.0 - p.1, warning: p.1, critical: p.0, notProbed: 0, pending: 0))
        }
    }

    private static func security(_ c: StatusCounts, _ pairs: [(Int, Int)], ago: TimeInterval = 120,
                                 running: Bool = false, bluetooth: BluetoothSummary? = nil) -> SnapshotEntry {
        let now = Date()
        let scannedAt = now.addingTimeInterval(-ago)
        let snapshot = WidgetSnapshot(version: WidgetSnapshot.schemaVersion, scannedAt: scannedAt, subnet: "192.168.1.0/24",
                                      counts: c, typeCounts: sixTypes, history: history(pairs, endingAt: scannedAt),
                                      newDevices: [], topology: [], topologyOverflow: 0, ownDeviceKey: nil,
                                      bluetooth: bluetooth)
        return SnapshotEntry(date: now, result: .loaded(snapshot), isScanRunning: running)
    }

    static var securityIssues: SnapshotEntry { security(counts(9, 2, 1, 3, 0), securityHistory) }
    static var securityAllClear: SnapshotEntry { security(counts(12, 0, 0, 2, 0), Array(repeating: (0, 0), count: 12), ago: 300) }
    static var securityChecking: SnapshotEntry { security(counts(9, 0, 0, 3, 2), [(0, 0), (0, 0), (0, 0)]) }
    static var securityNotProbed: SnapshotEntry { security(counts(0, 0, 0, 3, 0), [(0, 0)]) }
    static var securityFew: SnapshotEntry { security(counts(9, 2, 1, 3, 0), [(1, 2)]) }
    static var securityBusy: SnapshotEntry { security(counts(20, 30, 10, 3, 0), busyHistory) }
    static var securityStale: SnapshotEntry { security(counts(9, 2, 1, 3, 0), securityHistory, ago: 3 * 3600) }
    static var securityRunning: SnapshotEntry { security(counts(9, 2, 1, 3, 0), securityHistory, running: true) }
    static var securityNoDevices: SnapshotEntry { security(counts(0, 0, 0, 0, 0), []) }
    static var securityBluetooth: SnapshotEntry {
        security(counts(9, 2, 1, 3, 0), securityHistory, bluetooth: bluetooth(nearby: 7, ago: 720))
    }
    static var securityStaleBluetooth: SnapshotEntry {
        security(counts(9, 2, 1, 3, 0), securityHistory, bluetooth: bluetooth(nearby: 7, ago: 3 * 3600))
    }
    static var securityBothStaleBluetooth: SnapshotEntry {
        security(counts(9, 2, 1, 3, 0), securityHistory, ago: 3 * 3600, bluetooth: bluetooth(nearby: 17, ago: 23 * 3600))
    }
}
