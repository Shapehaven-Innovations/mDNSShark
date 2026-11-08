import Testing
import Foundation
import Combine
import DeviceFingerprint
import WidgetSnapshot
@testable import mDNSShark

@Suite("BLEPeripheralSet pull-to-refresh prune")
struct BLEPeripheralSetRefreshTests {
    let parser = BLEAdvertisementParser(companies: BLECompanyTable(text: "76\tApple, Inc."), services: BLEServiceNameTable(text: ""))
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    func sighting(_ name: String, at: Date) -> BLESighting {
        BLESighting(identifier: UUID(), fields: BLEAdvertisementFields(localName: name, manufacturerData: Data([0x4C, 0x00, 0x01])),
                    rssi: -60, at: at)
    }

    @discardableResult
    func ingest(_ set: inout BLEPeripheralSet, _ s: BLESighting) -> UUID {
        set.ingest(s, parsed: parser.parse(s.fields)).rowID
    }

    @Test func pruneDimmedUnsavedKeepsLiveSavedAndDimSaved() {
        var set = BLEPeripheralSet()
        let dim = ingest(&set, sighting("Dim", at: t0))
        let dimSaved = ingest(&set, sighting("Dim saved", at: t0))
        let live = ingest(&set, sighting("Live", at: t0 + 60))
        let liveSaved = ingest(&set, sighting("Live saved", at: t0 + 60))
        let edge = ingest(&set, sighting("Edge", at: t0 + 30))
        set.setSavedID(UUID(), for: dimSaved)
        set.setSavedID(UUID(), for: liveSaved)
        // "Edge" is exactly `dimAfter` old at t0 + 90, so it is already dimmed and goes too.
        let removed = set.pruneDimmedUnsaved(now: t0 + 30 + BLELifecycle.dimAfter)
        #expect(Set(removed) == [dim, edge])
        #expect(Set(set.peripherals.map(\.id)) == [dimSaved, live, liveSaved])
    }

    @Test func pruneDimmedUnsavedLeavesFreshRowsMarkedStale() {
        var set = BLEPeripheralSet()
        let fresh = ingest(&set, sighting("Fresh", at: t0))
        set.markAllStale()
        // A new scan dims every row, but only age decides the prune.
        #expect(set.pruneDimmedUnsaved(now: t0 + 10).isEmpty)
        #expect(set.peripherals.map(\.id) == [fresh])
    }

    @Test func pruneDimmedUnsavedCountsFromAgingAnchor() {
        var set = BLEPeripheralSet()
        ingest(&set, sighting("Away", at: t0))
        // Time spent with the app inactive does not age a row.
        set.shiftAging(by: 100)
        #expect(set.pruneDimmedUnsaved(now: t0 + 120).isEmpty)
        #expect(set.pruneDimmedUnsaved(now: t0 + 160).count == 1)
    }

    @Test func dropAfterIsTwoMinutes() {
        #expect(BLELifecycle.dropAfter == 120)
        #expect(BLELifecycle.of(lastSeen: t0, now: t0 + 119, markedStale: false) == .dim)
        #expect(BLELifecycle.of(lastSeen: t0, now: t0 + 120, markedStale: false) == .expired)
    }

    @Test func pruneExpiredStillKeepsSavedRowsAtTwoMinutes() {
        var set = BLEPeripheralSet()
        let keep = ingest(&set, sighting("Keep", at: t0))
        let drop = ingest(&set, sighting("Drop", at: t0))
        set.setSavedID(UUID(), for: keep)
        #expect(set.pruneExpired(now: t0 + 119).isEmpty)
        #expect(set.pruneExpired(now: t0 + 120) == [drop])
        #expect(set.peripherals.map(\.id) == [keep])
    }
}

@MainActor @Suite("BluetoothViewModel pull to refresh", .timeLimit(.minutes(1))) struct BluetoothRefreshTests {
    typealias H = BLEVMHarness

    /// Waits for the publish to show `rows` rows, with room for a loaded full-suite run.
    func settle(_ vm: BluetoothViewModel, rows: Int) async throws {
        try await H.waitUntil(.seconds(30)) { vm.peripherals.count == rows && !vm.hasPendingPublish }
        #expect(vm.peripherals.count == rows)
    }

    @Test func refreshWhileUndeterminedOrDeniedCreatesNoCentral() {
        for auth in [BLEAuthorization.undetermined, .denied, .restricted] {
            let (vm, factory, _) = H.makeVM(auth: auth)
            #expect(vm.refreshFromPull() == false)
            #expect(factory.created == 0)
            #expect(vm.isScanning == false)
            #expect(vm.lastScanSummary == nil)
        }
    }

    @Test func refreshWhileAllowedStartsExactlyOneScan() async throws {
        let (vm, factory, _) = H.makeVM(central: FakeBLECentral(powerState: .poweredOn))
        #expect(vm.refreshFromPull() == true)
        #expect(factory.created == 1)
        #expect(factory.fake.startCalls == [true])
        #expect(vm.isScanning)
        // Pulling again while the scan runs does not start a second one.
        #expect(vm.refreshFromPull() == true)
        #expect(factory.fake.startCalls == [true])
        #expect(factory.created == 1)
    }

    @Test func refreshDropsDimUnsavedRowsAndKeepsSavedAndLive() async throws {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let clock = Box(t0)
        let (vm, factory, _) = H.makeVM(now: { clock.value })
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "Old", at: t0)))
        factory.fake.subject.send(.sighting(H.sighting(name: "Garage", at: t0)))
        try await settle(vm, rows: 2)
        let garage = try #require(vm.peripherals.first { $0.displayName == "Garage" })
        let old = try #require(vm.peripherals.first { $0.displayName == "Old" })
        vm.addToDevices(garage.id)
        vm.stopScan(reason: .user)
        clock.value = t0 + 70
        factory.fake.subject.send(.sighting(H.sighting(name: "Fresh", at: t0 + 70)))
        try await settle(vm, rows: 3)
        #expect(vm.refreshFromPull())
        #expect(Set(vm.peripherals.map(\.displayName)) == ["Garage", "Fresh"])
        #expect(vm.peripheral(id: old.id) == nil)
        #expect(factory.fake.startCalls == [true, true])
        // A read on the pruned row finds nothing and connects to nothing.
        await vm.readDeviceInfo(old.id)
        #expect(factory.fake.readCalls.isEmpty)
        // Every peripheral is listed once and the saved entry is drawn as its live row only.
        let plan = DevicesListPlan.make(filter: .bluetooth, devices: [], peripherals: vm.peripherals, saved: vm.saved,
                                        matches: vm.matches, now: clock.value)
        let rows = plan.sections.flatMap(\.rows)
        #expect(rows.count == 2)
        #expect(Set(rows.map(\.id)).count == rows.count)
    }

    @Test func refreshWhenNoLongerAllowedPrunesNothing() async throws {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let clock = Box(t0)
        let (vm, factory, auth) = H.makeVM(now: { clock.value })
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "Old", at: t0)))
        try await settle(vm, rows: 1)
        vm.stopScan(reason: .user)
        clock.value = t0 + 70
        auth.value = .undetermined
        #expect(vm.refreshFromPull() == false)
        #expect(vm.peripherals.map(\.displayName) == ["Old"])
        #expect(factory.fake.startCalls == [true])
    }

    @Test func rematchAfterPruneDropsTheSuggestion() async throws {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let clock = Box(t0)
        let (vm, factory, _) = H.makeVM(now: { clock.value })
        vm.updateLANDevices([H.lan("Sonos Roam")])
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "Sonos Roam", company: H.sonos, at: t0)))
        try await settle(vm, rows: 1)
        vm.stopScan(reason: .user)
        #expect(!vm.suggestedLANDeviceIDs.isEmpty)
        #expect(vm.lastScanSummary?.suggested == 1)
        clock.value = t0 + 70
        vm.pruneDimmedUnsaved()
        #expect(vm.peripherals.isEmpty)
        #expect(vm.matches == .empty)
        // The Topology badge reads this set, so no stale badge is left behind.
        #expect(vm.suggestedLANDeviceIDs.isEmpty)
        #expect(vm.lastScanSummary?.nearby == 1)
        #expect(vm.lastScanSummary?.suggested == 0)
    }

    @Test func pruneDimmedUnsavedKeepsADimSavedSuggestion() async throws {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let clock = Box(t0)
        let (vm, factory, _) = H.makeVM(now: { clock.value })
        vm.updateLANDevices([H.lan("Sonos Roam")])
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "Sonos Roam", company: H.sonos, at: t0)))
        try await settle(vm, rows: 1)
        vm.addToDevices(try #require(vm.peripherals.first).id)
        vm.stopScan(reason: .user)
        clock.value = t0 + 70
        vm.pruneDimmedUnsaved()
        #expect(vm.peripherals.count == 1)
        #expect(!vm.suggestedLANDeviceIDs.isEmpty)
    }
}
