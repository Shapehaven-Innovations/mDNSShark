import Testing
import Foundation
import Combine
import DeviceFingerprint
import WidgetSnapshot
@testable import mDNSShark

@MainActor @Suite("Bluetooth summary freeze", .timeLimit(.minutes(1))) struct BluetoothSummaryFreezeTests {
    typealias H = BLEVMHarness

    @Test func rssiOnlyUpdateAfterScanLeavesSummary() async throws {
        let (vm, factory, _) = H.makeVM()
        let id = UUID()
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(id, name: "Lamp", rssi: -60)))
        try await H.settle(vm)
        vm.stopScan(reason: .user)
        let frozen = try #require(vm.lastScanSummary)
        factory.fake.subject.send(.sighting(H.sighting(id, name: "Lamp", rssi: -40)))
        try await H.settle(vm)
        #expect(vm.peripherals.first?.rssi == -40)
        #expect(vm.lastScanSummary == frozen)
    }

    @Test func droppedPeripheralLeavesNearby() async throws {
        let t0 = Date()
        let clock = Box(t0)
        let (vm, factory, _) = H.makeVM(now: { clock.value })
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "One", at: t0)))
        factory.fake.subject.send(.sighting(H.sighting(name: "Two", at: t0)))
        try await H.settle(vm)
        vm.stopScan(reason: .user)
        let frozen = try #require(vm.lastScanSummary)
        #expect(frozen.nearby == 2)
        // Past the two-minute drop a late sighting triggers a tick, and the prune drops the two old rows.
        clock.value = t0 + 400
        factory.fake.subject.send(.sighting(H.sighting(name: "Three", at: t0 + 400)))
        try await H.settle(vm)
        #expect(vm.peripherals.map(\.displayName) == ["Three"])
        #expect(vm.lastScanSummary == frozen)
    }

    @Test func widgetUpdateTable() async throws {
        let (vm, factory, auth) = H.makeVM()
        #expect(vm.widgetUpdate() == .keep)
        vm.startScanIfAuthorized()
        #expect(vm.widgetUpdate() == .keep)
        factory.fake.subject.send(.sighting(H.sighting(name: "Lamp")))
        vm.stopScan(reason: .user)
        let summary = try #require(vm.lastScanSummary)
        #expect(vm.widgetUpdate() == .set(summary))
        auth.value = .denied
        vm.scenePhaseChanged(isActive: false)
        vm.scenePhaseChanged(isActive: true)
        #expect(vm.authorization == .denied)
        #expect(vm.lastScanSummary == nil)
        #expect(vm.widgetUpdate() == .clear)
    }

    @Test func widgetUpdatesEmitsNothingForRSSI() async throws {
        let (vm, factory, _) = H.makeVM()
        let id = UUID()
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(id, name: "Sonos Roam", company: H.sonos)))
        try await H.settle(vm)
        vm.stopScan(reason: .user)
        let received = Box<[BluetoothSnapshotUpdate]>([])
        let sink = vm.widgetUpdates.sink { received.value.append($0) }
        for i in 0..<20 { factory.fake.subject.send(.sighting(H.sighting(id, name: "Sonos Roam", company: H.sonos, rssi: -40 - i))) }
        try await H.settle(vm)
        #expect(received.value.isEmpty)
        sink.cancel()
    }
}
