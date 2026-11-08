import Testing
import Foundation
import Combine
import WidgetSnapshot
@testable import mDNSShark

@MainActor
@Suite("WidgetSnapshotWriter")
struct WidgetSnapshotWriterTests {
    private final class Recorder { var kinds: [String] = [] }
    private final class Clock { var date: Date; init(_ d: Date) { date = d } }

    private let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    private func device(_ ip: String, mac: String? = nil, gateway: Bool? = nil, onSubnet: Bool? = true,
                        host: String? = nil, settled: Bool = true) -> DiscoveredDevice {
        var d = DiscoveredDevice(hostname: host ?? ip, ipAddress: ip, macAddress: mac, probesSettled: settled)
        d.isDefaultGateway = gateway
        d.isOnLocalSubnet = onSubnet
        return d
    }

    private func tempStore() -> SnapshotStore {
        SnapshotStore(directory: FileManager.default.temporaryDirectory.appendingPathComponent("wsw-" + UUID().uuidString))
    }

    private func makeWriter(store: SnapshotStore?, recorder: Recorder, clock: Clock,
                            debounce: Duration = .milliseconds(50), flags: UserDefaults? = nil) -> WidgetSnapshotWriter {
        WidgetSnapshotWriter(store: store, reload: { recorder.kinds.append($0) }, debounce: debounce, now: { clock.date },
                             flagDefaults: flags ?? Self.tempDefaults())
    }

    private static func tempDefaults() -> UserDefaults {
        UserDefaults(suiteName: "WidgetSnapshotWriterTests.\(UUID().uuidString)")!
    }

    private func input(_ devices: [DiscoveredDevice], status: @escaping (DiscoveredDevice) -> SecurityStatus = { _ in .secure },
                       own: Set<String> = [], subnet: String? = nil) -> WidgetSnapshotWriter.Input {
        .init(devices: devices, status: status, ownAddressKeys: own, subnet: subnet)
    }

    private func loaded(_ store: SnapshotStore) -> WidgetSnapshot? {
        if case .loaded(let s) = store.loadSnapshot() { return s }
        return nil
    }

    @Test("scan end writes the snapshot and reloads every scan kind")
    func writesOnScanEnd() {
        let store = tempStore(), rec = Recorder()
        let writer = makeWriter(store: store, recorder: rec, clock: Clock(t0))
        writer.scanDidFinish(input([device("192.168.1.1"), device("192.168.1.2"), device("192.168.1.3")]))
        let snap = loaded(store)
        #expect(snap?.counts.total == 3)
        #expect(snap?.history.count == 1)
        #expect(snap?.scannedAt == t0)
        #expect(rec.kinds == WidgetKind.scanKinds)
    }

    @Test("counts map every SecurityStatus, and not probed and pending are never secure")
    func countsMap() {
        let devices = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5"].map { device($0) }
        let statuses: [String: SecurityStatus] = ["192.168.1.1": .secure, "192.168.1.2": .warning, "192.168.1.3": .critical,
                                                  "192.168.1.4": .notProbed, "192.168.1.5": .pending]
        let result = WidgetSnapshotWriter.makeSnapshot(input: input(devices, status: { statuses[$0.ipAddress]! }),
                                                       previous: nil, seen: [:], now: t0, newScan: true)
        #expect(result.snapshot.counts == StatusCounts(total: 5, secure: 1, warning: 1, critical: 1, notProbed: 1, pending: 1))
    }

    @Test("the phone's own row is counted and keyed")
    func ownRowCounted() {
        let devices = [device("192.168.1.20", mac: "AA:BB:CC:00:00:01"), device("192.168.1.1")]
        let result = WidgetSnapshotWriter.makeSnapshot(input: input(devices, own: ["192.168.1.20"]),
                                                       previous: nil, seen: [:], now: t0, newScan: true)
        #expect(result.snapshot.counts.total == 2)
        #expect(result.snapshot.ownDeviceKey == "aa:bb:cc:00:00:01")
    }

    @Test("type counts list present types only, by DeviceType.label")
    func typeCounts() {
        let devices = [device("192.168.1.1", gateway: true), device("192.168.1.77", gateway: false)]
        let result = WidgetSnapshotWriter.makeSnapshot(input: input(devices), previous: nil, seen: [:], now: t0, newScan: true)
        #expect(result.snapshot.typeCounts == ["Router": 1, "Unknown": 1])
    }

    @Test("topology puts the gateway first, on-network before off-network, max 12 with overflow")
    func topologyOrder() {
        var devices: [DiscoveredDevice] = (0..<14).map { device("10.0.0.\($0 + 10)", gateway: false) }
        devices[0].isOnLocalSubnet = false
        devices[1].isOnLocalSubnet = false
        devices[3].isDefaultGateway = true
        let result = WidgetSnapshotWriter.makeSnapshot(input: input(devices), previous: nil, seen: [:], now: t0, newScan: true)
        #expect(result.snapshot.topology.count == 12)
        #expect(result.snapshot.topology[0].isGateway)
        #expect(result.snapshot.topology.allSatisfy { !$0.offNetwork })
        #expect(result.snapshot.topologyOverflow == 2)

        var small: [DiscoveredDevice] = (0..<5).map { device("10.0.0.\($0 + 10)", gateway: false) }
        small[0].isOnLocalSubnet = false
        small[1].isOnLocalSubnet = false
        small[3].isDefaultGateway = true
        let topo = WidgetSnapshotWriter.makeSnapshot(input: input(small), previous: nil, seen: [:], now: t0, newScan: true).snapshot.topology
        #expect(topo.count == 5)
        #expect(topo[0].isGateway)
        #expect(topo.suffix(2).allSatisfy { $0.offNetwork })
        #expect(topo.prefix(3).allSatisfy { !$0.offNetwork })
    }

    @Test("literal values are stored as received")
    func literals() {
        let devices = [device("fe80::1%en0", host: "Ana's iPhone (2)")]
        let result = WidgetSnapshotWriter.makeSnapshot(input: input(devices, subnet: "10.0.0.0/23"),
                                                       previous: nil, seen: [:], now: t0, newScan: true)
        #expect(result.snapshot.topology[0].name == "Ana's iPhone (2)")
        #expect(result.snapshot.topology[0].ip == "fe80::1%en0")
        #expect(result.snapshot.subnet == "10.0.0.0/23")
    }

    @Test("new devices are those first seen within 24 h, newest first, max 6")
    func newDevices() {
        let old = "aa:bb:cc:00:00:01"
        var devices = [device("192.168.1.2", mac: "AA:BB:CC:00:00:01")]
        var seen: [String: Date] = [old: t0.addingTimeInterval(-25 * 3600)]
        for i in 0..<8 {
            let mac = "aa:bb:cc:00:01:0\(i)"
            devices.append(device("192.168.1.1\(i)", mac: mac))
            seen[mac] = t0.addingTimeInterval(-Double(i + 1) * 60)
        }
        let result = WidgetSnapshotWriter.makeSnapshot(input: input(devices), previous: nil, seen: seen, now: t0, newScan: true)
        let list = result.snapshot.newDevices
        #expect(list.count == 6)
        #expect(!list.contains { $0.key == old })
        #expect(list.map(\.firstSeen) == list.map(\.firstSeen).sorted(by: >))
    }

    @Test("history keeps 12 across scans")
    func ringAcrossScans() {
        let store = tempStore(), rec = Recorder(), clock = Clock(t0)
        let writer = makeWriter(store: store, recorder: rec, clock: clock)
        for i in 0..<13 {
            clock.date = t0.addingTimeInterval(Double(i) * 60)
            writer.scanDidFinish(input([device("192.168.1.1")]))
        }
        #expect(loaded(store)?.history.count == 12)
    }

    @Test("a late rewrite replaces the newest sample and keeps scannedAt")
    func rewriteReplacesNewestSample() async throws {
        let store = tempStore(), rec = Recorder(), clock = Clock(t0)
        let writer = makeWriter(store: store, recorder: rec, clock: clock)
        writer.scanDidFinish(input([device("192.168.1.1", settled: false)], status: { _ in .pending }))
        clock.date = t0.addingTimeInterval(30)
        writer.scheduleRewrite { self.input([self.device("192.168.1.1")], status: { _ in .secure }) }
        try await Task.sleep(for: .milliseconds(300))
        let snap = loaded(store)
        #expect(snap?.history.count == 1)
        #expect(snap?.history.last?.counts.secure == 1)
        #expect(snap?.scannedAt == t0)
    }

    @Test("rewrites are debounced into one write")
    func debounce() async throws {
        let store = tempStore(), rec = Recorder()
        let writer = makeWriter(store: store, recorder: rec, clock: Clock(t0))
        writer.scanDidFinish(input([device("192.168.1.1")]))
        rec.kinds.removeAll()
        // A different status each time, so only the debounce can collapse them, and the last one must win.
        for status in [SecurityStatus.warning, .warning, .critical] {
            writer.scheduleRewrite { self.input([self.device("192.168.1.1")], status: { _ in status }) }
            try await Task.sleep(for: .milliseconds(10))
        }
        try await Task.sleep(for: .milliseconds(300))
        #expect(rec.kinds == WidgetKind.scanKinds)
        let counts = loaded(store)?.counts
        #expect(counts?.critical == 1 && counts?.warning == 0 && counts?.secure == 0)
    }

    @Test("a rewrite with nil input or before any scan writes nothing")
    func rewriteSkips() async throws {
        let store = tempStore(), rec = Recorder()
        let writer = makeWriter(store: store, recorder: rec, clock: Clock(t0))
        writer.scheduleRewrite { self.input([self.device("192.168.1.1")]) }
        try await Task.sleep(for: .milliseconds(300))
        #expect(store.loadSnapshot() == .missing)
        #expect(rec.kinds.isEmpty)

        writer.scanDidFinish(input([device("192.168.1.1")]))
        let before = rec.kinds.count
        writer.scheduleRewrite { nil }
        try await Task.sleep(for: .milliseconds(300))
        #expect(rec.kinds.count == before)
    }

    @Test("the write verdict keeps the previous snapshot for a denied, unconfirmed background or empty scan")
    func verdictTable() {
        typealias G = WidgetSnapshotGuard
        #expect(G.verdict(deviceCount: 3, permission: .granted, deniedBanner: false, requiresGrant: true, hasPrevious: true) == .write)
        #expect(G.verdict(deviceCount: 3, permission: nil, deniedBanner: false, requiresGrant: false, hasPrevious: true) == .write)
        #expect(G.verdict(deviceCount: 3, permission: .undetermined, deniedBanner: false, requiresGrant: false, hasPrevious: true) == .write)
        // Denied: never written, with or without an older snapshot, in the foreground or background.
        for previous in [false, true] {
            for background in [false, true] {
                #expect(G.verdict(deviceCount: 1, permission: .denied, deniedBanner: true, requiresGrant: background, hasPrevious: previous) == .keepPrevious)
            }
        }
        // A banner still up from an earlier denial counts until this scan's check comes back granted.
        #expect(G.verdict(deviceCount: 1, permission: nil, deniedBanner: true, requiresGrant: false, hasPrevious: true) == .keepPrevious)
        #expect(G.verdict(deviceCount: 1, permission: .undetermined, deniedBanner: true, requiresGrant: false, hasPrevious: true) == .keepPrevious)
        #expect(G.verdict(deviceCount: 4, permission: .granted, deniedBanner: true, requiresGrant: false, hasPrevious: true) == .write)
        // In the background only a confirmed grant may replace the snapshot.
        #expect(G.verdict(deviceCount: 4, permission: nil, deniedBanner: false, requiresGrant: true, hasPrevious: true) == .keepPrevious)
        #expect(G.verdict(deviceCount: 4, permission: .undetermined, deniedBanner: false, requiresGrant: true, hasPrevious: false) == .keepPrevious)
        // An empty result never replaces a real one; with nothing earlier it is written as is.
        #expect(G.verdict(deviceCount: 0, permission: .granted, deniedBanner: false, requiresGrant: false, hasPrevious: true) == .keepPrevious)
        #expect(G.verdict(deviceCount: 0, permission: .granted, deniedBanner: false, requiresGrant: false, hasPrevious: false) == .write)
    }

    @Test("a denied scan keeps the previous snapshot, clears the spinner and reloads")
    func deniedKeepsPrevious() {
        let store = tempStore(), rec = Recorder(), clock = Clock(t0), flags = Self.tempDefaults()
        let writer = makeWriter(store: store, recorder: rec, clock: clock, flags: flags)
        writer.scanDidFinish(input([device("192.168.1.1"), device("192.168.1.2")]))
        rec.kinds.removeAll()

        clock.date = t0.addingTimeInterval(600)
        ScanRequestFlag.markRunning(in: flags, at: clock.date)
        var denied = input([device("192.168.1.1")])
        denied.localNetwork = .denied
        denied.localNetworkDeniedBanner = true
        writer.scanDidFinish(denied)

        let snap = loaded(store)
        #expect(snap?.counts.total == 2)
        #expect(snap?.scannedAt == t0)
        #expect(snap?.history.count == 1)
        #expect(ScanRequestFlag.awaitingUntil(in: flags, scannedAt: snap?.scannedAt, now: clock.date) == nil)
        #expect(rec.kinds == WidgetKind.scanKinds)
    }

    @Test("a denied first scan writes nothing")
    func deniedFirstScan() {
        let store = tempStore(), rec = Recorder()
        let writer = makeWriter(store: store, recorder: rec, clock: Clock(t0))
        var denied = input([device("192.168.1.1")])
        denied.localNetwork = .denied
        writer.scanDidFinish(denied)
        #expect(store.loadSnapshot() == .missing)
    }

    @Test("a background scan without a confirmed grant keeps the previous snapshot")
    func backgroundUnconfirmed() {
        let store = tempStore(), rec = Recorder(), clock = Clock(t0)
        let writer = makeWriter(store: store, recorder: rec, clock: clock)
        writer.scanDidFinish(input([device("192.168.1.1"), device("192.168.1.2")]))
        clock.date = t0.addingTimeInterval(60)
        var background = input([device("192.168.1.1")])
        background.requiresConfirmedGrant = true
        writer.scanDidFinish(background)
        #expect(loaded(store)?.counts.total == 2)

        background.localNetwork = .granted
        writer.scanDidFinish(background)
        #expect(loaded(store)?.counts.total == 1)
        #expect(loaded(store)?.scannedAt == clock.date)
    }

    @Test("an empty scan keeps the previous snapshot")
    func emptyKeepsPrevious() {
        let store = tempStore(), rec = Recorder(), clock = Clock(t0)
        let writer = makeWriter(store: store, recorder: rec, clock: clock)
        writer.scanDidFinish(input([device("192.168.1.1")]))
        clock.date = t0.addingTimeInterval(60)
        writer.scanDidFinish(input([]))
        #expect(loaded(store)?.counts.total == 1)
        #expect(loaded(store)?.scannedAt == t0)
    }

    @Test("a late rewrite after a denial does not replace the snapshot")
    func rewriteAfterDenial() async throws {
        let store = tempStore(), rec = Recorder()
        let writer = makeWriter(store: store, recorder: rec, clock: Clock(t0))
        writer.scanDidFinish(input([device("192.168.1.1"), device("192.168.1.2")]))
        writer.scheduleRewrite {
            var denied = self.input([self.device("192.168.1.1")])
            denied.localNetwork = .denied
            return denied
        }
        try await Task.sleep(for: .milliseconds(300))
        #expect(loaded(store)?.counts.total == 2)
    }

    @Test("no store means no crash and no reload")
    func noStore() {
        let rec = Recorder()
        let writer = makeWriter(store: nil, recorder: rec, clock: Clock(t0))
        writer.scanDidFinish(input([device("192.168.1.1")]))
        #expect(rec.kinds.isEmpty)
    }

    @Test("rewrite triggers drop the devices and findings seeds, and fire on the Bluetooth publisher's first value")
    func triggersDropSeedsAndFireOnBluetooth() {
        let devices = CurrentValueSubject<Int, Never>(0), findings = CurrentValueSubject<Int, Never>(0)
        // Seedless like `BluetoothViewModel.widgetUpdates`, which already ends in dropFirst().
        let bluetooth = PassthroughSubject<BluetoothSnapshotUpdate, Never>()
        var fired = 0
        let c = WidgetSnapshotWriter.rewriteTriggers(devices: devices, findings: findings, bluetooth: bluetooth).sink { fired += 1 }
        #expect(fired == 0)
        bluetooth.send(.set(summary))
        #expect(fired == 1)
        findings.send(1)
        #expect(fired == 2)
        devices.send(1)
        #expect(fired == 3)
        bluetooth.send(.clear)
        #expect(fired == 4)
        c.cancel()
    }

    @Test("a findings-only rewrite changes the statuses, replaces the newest sample and keeps scannedAt")
    func findingsRewrite() async throws {
        let store = tempStore(), rec = Recorder(), clock = Clock(t0)
        let writer = makeWriter(store: store, recorder: rec, clock: clock)
        let rows = [device("192.168.1.1"), device("192.168.1.2")]
        writer.scanDidFinish(input(rows))
        clock.date = t0.addingTimeInterval(600)
        writer.scheduleRewrite { self.input(rows, status: { $0.ipAddress == "192.168.1.2" ? .critical : .secure }) }
        try await Task.sleep(for: .milliseconds(300))
        let snap = loaded(store)
        #expect(snap?.counts.critical == 1 && snap?.counts.secure == 1)
        #expect(snap?.history.count == 1 && snap?.history.last?.counts.critical == 1)
        #expect(snap?.scannedAt == t0)
        #expect(rec.kinds.suffix(WidgetKind.scanKinds.count) == ArraySlice(WidgetKind.scanKinds))
    }

    private let summary = BluetoothSummary(scannedAt: Date(timeIntervalSince1970: 1_800_000_100), nearby: 5, suggested: 2)

    private func btInput(_ update: BluetoothSnapshotUpdate) -> WidgetSnapshotWriter.Input {
        var i = input([device("192.168.1.1")])
        i.bluetooth = update
        return i
    }

    @Test("scan end stores a set Bluetooth summary")
    func scanEndStoresSetSummary() {
        let store = tempStore()
        let writer = makeWriter(store: store, recorder: Recorder(), clock: Clock(t0))
        writer.scanDidFinish(btInput(.set(summary)))
        #expect(loaded(store)?.bluetooth == summary)
    }

    @Test("keep preserves the previous summary")
    func keepPreservesPreviousSummary() {
        let store = tempStore(), clock = Clock(t0)
        let writer = makeWriter(store: store, recorder: Recorder(), clock: clock)
        writer.scanDidFinish(btInput(.set(summary)))
        clock.date = t0.addingTimeInterval(60)
        writer.scanDidFinish(btInput(.keep))
        #expect(loaded(store)?.bluetooth == summary)
    }

    @Test("clear removes the summary")
    func clearRemovesSummary() {
        let store = tempStore(), clock = Clock(t0)
        let writer = makeWriter(store: store, recorder: Recorder(), clock: clock)
        writer.scanDidFinish(btInput(.set(summary)))
        clock.date = t0.addingTimeInterval(60)
        writer.scanDidFinish(btInput(.clear))
        #expect(loaded(store) != nil)
        #expect(loaded(store)?.bluetooth == nil)
    }

    @Test("a rewrite whose only change is Bluetooth writes once and reloads the scan kinds")
    func bluetoothOnlyRewriteWritesOnceAndReloads() async throws {
        let store = tempStore(), rec = Recorder(), clock = Clock(t0)
        let writer = makeWriter(store: store, recorder: rec, clock: clock)
        writer.scanDidFinish(btInput(.keep))
        rec.kinds.removeAll()
        clock.date = t0.addingTimeInterval(120)
        // A different summary each time, so only the debounce can collapse them, and the last one must win.
        let first = BluetoothSummary(scannedAt: summary.scannedAt, nearby: 3, suggested: 0)
        let second = BluetoothSummary(scannedAt: summary.scannedAt, nearby: 4, suggested: 1)
        for update in [first, second, summary] {
            writer.scheduleRewrite { self.btInput(.set(update)) }
            try await Task.sleep(for: .milliseconds(10))
        }
        try await Task.sleep(for: .milliseconds(300))
        let snap = loaded(store)
        #expect(snap?.bluetooth == summary)
        #expect(snap?.scannedAt == t0 && snap?.history.count == 1)
        #expect(rec.kinds == WidgetKind.scanKinds)
    }

    @Test("a rewrite with unchanged input saves nothing and reloads nothing, also for a fractional-second Bluetooth date",
          arguments: [0.0, 0.123_456_789])
    func unchangedRewriteSavesNothing(fraction: Double) async throws {
        let store = tempStore(), rec = Recorder(), clock = Clock(t0)
        let writer = makeWriter(store: store, recorder: rec, clock: clock)
        let summary = BluetoothSummary(scannedAt: self.summary.scannedAt.addingTimeInterval(fraction), nearby: 5, suggested: 2)
        writer.scanDidFinish(btInput(.set(summary)))
        let file = store.directory.appendingPathComponent(SnapshotStore.snapshotFile)
        let before = try Data(contentsOf: file)
        let modified = try FileManager.default.attributesOfItem(atPath: file.path)[.modificationDate] as? Date
        rec.kinds.removeAll()
        clock.date = t0.addingTimeInterval(120)
        writer.scheduleRewrite { self.btInput(.set(summary)) }
        try await Task.sleep(for: .milliseconds(300))
        writer.scheduleRewrite { self.btInput(.keep) }
        try await Task.sleep(for: .milliseconds(300))
        #expect(try Data(contentsOf: file) == before)
        #expect(try FileManager.default.attributesOfItem(atPath: file.path)[.modificationDate] as? Date == modified)
        #expect(rec.kinds.isEmpty)
    }

    @Test("keep with no previous snapshot leaves it nil")
    func keepWithNoPreviousIsNil() {
        let store = tempStore()
        let writer = makeWriter(store: store, recorder: Recorder(), clock: Clock(t0))
        writer.scanDidFinish(btInput(.keep))
        #expect(loaded(store) != nil)
        #expect(loaded(store)?.bluetooth == nil)
    }
}
