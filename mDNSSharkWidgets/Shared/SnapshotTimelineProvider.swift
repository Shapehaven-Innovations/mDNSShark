import WidgetKit
import Foundation
import WidgetSnapshot

struct SnapshotEntry: TimelineEntry {
    let date: Date
    let result: SnapshotDecodeResult<WidgetSnapshot>
    let isScanRunning: Bool
}

/// Shared by every scan widget. It only reads the App Group snapshot and the scan request date.
struct SnapshotTimelineProvider: TimelineProvider {
    func placeholder(in context: Context) -> SnapshotEntry { WidgetSamples.fresh }

    func getSnapshot(in context: Context, completion: @escaping (SnapshotEntry) -> Void) {
        let now = Date()
        let result = Self.load()
        if case .loaded = result {
            completion(SnapshotEntry(date: now, result: result, isScanRunning: Self.awaitingUntil(result, now: now) != nil))
        } else if context.isPreview {
            completion(WidgetSamples.fresh)
        } else {
            completion(SnapshotEntry(date: now, result: result, isScanRunning: Self.awaitingUntil(result, now: now) != nil))
        }
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<SnapshotEntry>) -> Void) {
        let now = Date()
        let result = Self.load()
        let plan = WidgetTimelinePlan.make(scannedAt: Self.scannedAt(result), now: now,
                                           awaitingUntil: Self.awaitingUntil(result, now: now),
                                           bluetoothScannedAt: Self.bluetoothScannedAt(result))
        let entries = plan.entries.map { SnapshotEntry(date: $0.date, result: result, isScanRunning: $0.isScanRunning) }
        completion(Timeline(entries: entries, policy: .after(plan.reloadAfter)))
    }

    private static func load() -> SnapshotDecodeResult<WidgetSnapshot> {
        SnapshotStore.appGroup()?.loadSnapshot() ?? .missing
    }

    private static func scannedAt(_ result: SnapshotDecodeResult<WidgetSnapshot>) -> Date? {
        if case .loaded(let snapshot) = result { return snapshot.scannedAt }
        return nil
    }

    private static func bluetoothScannedAt(_ result: SnapshotDecodeResult<WidgetSnapshot>) -> Date? {
        if case .loaded(let snapshot) = result { return snapshot.bluetooth?.scannedAt }
        return nil
    }

    private static func awaitingUntil(_ result: SnapshotDecodeResult<WidgetSnapshot>, now: Date) -> Date? {
        ScanRequestFlag.awaitingUntil(in: UserDefaults(suiteName: AppGroup.identifier) ?? .standard,
                                      scannedAt: scannedAt(result), now: now)
    }
}
