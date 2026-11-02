import Testing
import Foundation
@testable import WidgetSnapshot

@Suite("Snapshot store")
struct SnapshotStoreTests {
    func makeStore() -> SnapshotStore {
        SnapshotStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString))
    }
    func makeDefaults() -> UserDefaults { UserDefaults(suiteName: "WidgetSnapshotTests.\(UUID().uuidString)")! }
    let t = Date(timeIntervalSince1970: 1_000_000)

    @Test("no file gives missing")
    func missing() {
        let store = makeStore()
        #expect(store.loadSnapshot() == .missing)
        #expect(store.loadCapture() == .missing)
        #expect(store.loadSeen() == [:])
    }

    @Test("save then load round trips")
    func saveLoad() throws {
        let store = makeStore()
        try store.save(SnapshotCodingTests.sample)
        #expect(store.loadSnapshot() == .loaded(SnapshotCodingTests.sample))
    }

    @Test("a newer file on disk reads as newer")
    func newer() throws {
        let store = makeStore()
        try FileManager.default.createDirectory(at: store.directory, withIntermediateDirectories: true)
        try Data(#"{"version":9}"#.utf8).write(to: store.directory.appendingPathComponent(SnapshotStore.snapshotFile))
        #expect(store.loadSnapshot() == .newer(version: 9))
    }

    @Test("save trims to 64 KB")
    func saveTrims() throws {
        let store = makeStore()
        let long = String(repeating: "h", count: 4000)
        let briefs = (0..<12).map { i in
            DeviceBrief(key: "k\(i)", name: long, ip: "192.168.1.\(i)", typeLabel: "TV", symbol: "tv", status: "not probed",
                        offNetwork: false, isGateway: false, firstSeen: Date(timeIntervalSince1970: Double(i)))
        }
        let s = WidgetSnapshot(version: 1, scannedAt: Date(timeIntervalSince1970: 100), subnet: nil, counts: .zero,
                               typeCounts: [:], history: [], newDevices: Array(briefs.prefix(6)), topology: briefs,
                               topologyOverflow: 0, ownDeviceKey: nil)
        #expect(try SnapshotCoding.encode(s).count > 65_536)
        try store.save(s)
        guard case .loaded(let back) = store.loadSnapshot() else { Issue.record("not loaded"); return }
        #expect(back.topology.count < 12)
        let size = try FileManager.default.attributesOfItem(atPath: store.directory.appendingPathComponent(SnapshotStore.snapshotFile).path)[.size] as! Int
        #expect(size <= 65_536)
    }

    @Test("seen map round trips")
    func seen() throws {
        let store = makeStore()
        let d = Date(timeIntervalSince1970: 42.5)
        try store.saveSeen(["aa:bb": d])
        #expect(store.loadSeen() == ["aa:bb": d])
    }

    @Test("a fresh scan request is consumed once")
    func freshRequest() {
        let defaults = makeDefaults()
        ScanRequestFlag.stamp(in: defaults, at: t)
        #expect(ScanRequestFlag.consume(from: defaults, now: t + 5))
        #expect(!ScanRequestFlag.consume(from: defaults, now: t + 6))
        #expect(defaults.object(forKey: ScanRequestFlag.key) == nil)
    }

    @Test("a request older than 120 s is dropped and cleared")
    func staleRequestIgnored() {
        let defaults = makeDefaults()
        ScanRequestFlag.stamp(in: defaults, at: t)
        #expect(!ScanRequestFlag.consume(from: defaults, now: t + 121))
        #expect(defaults.object(forKey: ScanRequestFlag.key) == nil)
    }

    @Test("a request dated in the future is dropped")
    func futureRequest() {
        let defaults = makeDefaults()
        ScanRequestFlag.stamp(in: defaults, at: t + 60)
        #expect(!ScanRequestFlag.consume(from: defaults, now: t))
    }

    @Test("consume leaves the last request so the widget can still see it")
    func lastRequestSurvivesConsume() {
        let d = makeDefaults(); let t = Date(timeIntervalSince1970: 10_000)
        ScanRequestFlag.stamp(in: d, at: t)
        _ = ScanRequestFlag.consume(from: d, now: t)
        #expect(d.object(forKey: ScanRequestFlag.lastRequestKey) as? Date == t)
    }

    @Test("awaiting runs from the request until maxAge when no newer snapshot exists")
    func awaitingWindow() {
        let d = makeDefaults(); let t = Date(timeIntervalSince1970: 10_000)
        ScanRequestFlag.stamp(in: d, at: t)
        #expect(ScanRequestFlag.awaitingUntil(in: d, scannedAt: nil, now: t.addingTimeInterval(5)) == t.addingTimeInterval(120))
        #expect(ScanRequestFlag.awaitingUntil(in: d, scannedAt: t.addingTimeInterval(-600), now: t) == t.addingTimeInterval(120))
    }

    @Test("a snapshot newer than the request clears awaiting")
    func awaitingClearsOnNewerSnapshot() {
        let d = makeDefaults(); let t = Date(timeIntervalSince1970: 10_000)
        ScanRequestFlag.stamp(in: d, at: t)
        #expect(ScanRequestFlag.awaitingUntil(in: d, scannedAt: t.addingTimeInterval(30), now: t.addingTimeInterval(31)) == nil)
    }

    @Test("awaiting times out after maxAge and ignores future stamps")
    func awaitingTimesOut() {
        let d = makeDefaults(); let t = Date(timeIntervalSince1970: 10_000)
        ScanRequestFlag.stamp(in: d, at: t)
        #expect(ScanRequestFlag.awaitingUntil(in: d, scannedAt: nil, now: t.addingTimeInterval(121)) == nil)
        #expect(ScanRequestFlag.awaitingUntil(in: d, scannedAt: nil, now: t.addingTimeInterval(-1)) == nil)
        #expect(ScanRequestFlag.awaitingUntil(in: makeDefaults(), scannedAt: nil, now: t) == nil)
    }

    @Test("marking a background scan running shows the spinner but leaves nothing to consume")
    func markRunning() {
        let d = makeDefaults(); let t = Date(timeIntervalSince1970: 10_000)
        ScanRequestFlag.markRunning(in: d, at: t)
        #expect(ScanRequestFlag.awaitingUntil(in: d, scannedAt: nil, now: t.addingTimeInterval(5)) == t.addingTimeInterval(120))
        #expect(!ScanRequestFlag.consume(from: d, now: t))
        #expect(ScanRequestFlag.awaitingUntil(in: d, scannedAt: t.addingTimeInterval(20), now: t.addingTimeInterval(21)) == nil)
    }

    @Test("clearing the running mark hides the spinner and keeps a stamped flag")
    func clearRunning() {
        let d = makeDefaults(); let t = Date(timeIntervalSince1970: 10_000)
        ScanRequestFlag.stamp(in: d, at: t)
        ScanRequestFlag.clearRunning(in: d)
        #expect(ScanRequestFlag.awaitingUntil(in: d, scannedAt: nil, now: t.addingTimeInterval(5)) == nil)
        #expect(ScanRequestFlag.consume(from: d, now: t.addingTimeInterval(5)))
    }

    @Test("the widget link opens the Devices tab")
    func devicesLink() {
        #expect(WidgetLink.devicesTab.absoluteString == "mdnsshark://tab/devices")
    }
}
