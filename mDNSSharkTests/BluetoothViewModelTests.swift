import Testing
import Foundation
import Combine
import DeviceFingerprint
import WidgetSnapshot
@testable import mDNSShark

/// Shared helpers for the Bluetooth view model suites.
@MainActor
enum BLEVMHarness {
    nonisolated static let sonos: UInt16 = 0x05A7
    nonisolated static let apple: UInt16 = 0x004C
    static let parser = BLEAdvertisementParser(companies: BLECompanyTable(text: "76\tApple, Inc.\n1447\tSonos, Inc."),
                                               services: BLEServiceNameTable(text: ""))

    static func tempStore() -> BLEDeviceStore {
        BLEDeviceStore(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("ble-vm-\(UUID().uuidString)/saved.json"))
    }

    static func makeVM(auth: BLEAuthorization = .allowed, central: FakeBLECentral? = nil,
                       store: BLEDeviceStore? = nil, now: (() -> Date)? = nil)
        -> (vm: BluetoothViewModel, factory: CentralFactory, auth: Box<BLEAuthorization>) {
        let factory = CentralFactory(central ?? FakeBLECentral())
        let authBox = Box(auth)
        let vm = BluetoothViewModel(makeCentral: { factory.make() }, authorization: { authBox.value },
                                    store: store ?? tempStore(), parser: parser, now: now ?? Date.init,
                                    publishInterval: .milliseconds(20))
        return (vm, factory, authBox)
    }

    static func sighting(_ id: UUID = UUID(), name: String? = nil, company: UInt16 = apple, rssi: Int = -60, at: Date = Date()) -> BLESighting {
        let mfg = Data([UInt8(company & 0xFF), UInt8(company >> 8), 0x01])
        return BLESighting(identifier: id, fields: BLEAdvertisementFields(localName: name, manufacturerData: mfg), rssi: rssi, at: at)
    }

    /// Polls until `condition` holds or `timeout` passes, so slow parallel runs do not race fixed sleeps.
    static func waitUntil(_ timeout: Duration = .seconds(30), _ condition: () -> Bool) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now + timeout
        while !condition(), clock.now < deadline { try await Task.sleep(for: .milliseconds(5)) }
    }

    /// Waits for the 20 ms publish tick to drain every pending sighting.
    static func settle(_ vm: BluetoothViewModel) async throws {
        try await Task.sleep(for: .milliseconds(5))
        try await waitUntil { !vm.hasPendingPublish }
    }
}

@MainActor @Suite("BluetoothViewModel", .timeLimit(.minutes(1))) struct BluetoothViewModelTests {
    typealias H = BLEVMHarness

    @Test func deniedNeverCreatesCentralOrScans() async {
        for auth in [BLEAuthorization.denied, .restricted] {
            let (vm, factory, _) = H.makeVM(auth: auth)
            vm.allowAndScan()
            #expect(factory.created == 0)
            #expect(vm.isScanning == false)
            #expect(vm.authorization == auth)
            #expect(vm.widgetUpdate() == .clear)
            #expect(vm.startScanIfAuthorized() == false)
            #expect(factory.created == 0)
        }
    }

    @Test func headerPathNeverCreatesCentralWhenUndetermined() {
        let (vm, factory, _) = H.makeVM(auth: .undetermined)
        #expect(vm.startScanIfAuthorized() == false)
        #expect(factory.created == 0)
        #expect(vm.isScanning == false)
    }

    @Test func headerPathScansWhenAllowed() {
        let (vm, factory, _) = H.makeVM(auth: .allowed, central: FakeBLECentral(powerState: .poweredOn))
        #expect(vm.startScanIfAuthorized() == true)
        #expect(factory.created == 1)
        #expect(factory.fake.startCalls == [true])
        #expect(vm.isScanning)
        #expect(vm.powerState == .poweredOn)
        // A second call while scanning does not start twice or make another central.
        #expect(vm.startScanIfAuthorized() == true)
        #expect(factory.fake.startCalls == [true])
        #expect(factory.created == 1)
    }

    @Test func allowAndScanWaitsForPowerOn() {
        let (vm, factory, auth) = H.makeVM(auth: .undetermined, central: FakeBLECentral(powerState: .unknown))
        vm.allowAndScan()
        #expect(factory.created == 1)
        #expect(factory.fake.startCalls.isEmpty)
        #expect(vm.isScanning == false)
        auth.value = .allowed
        factory.fake.power(.poweredOn)
        #expect(factory.fake.startCalls == [true])
        #expect(vm.isScanning)
        #expect(vm.authorization == .allowed)
        #expect(vm.powerState == .poweredOn)
    }

    @Test func promptAnsweredWithDenyNeverScans() {
        let (vm, factory, auth) = H.makeVM(auth: .undetermined, central: FakeBLECentral(powerState: .unknown))
        vm.allowAndScan()
        auth.value = .denied
        factory.fake.power(.unknown)
        #expect(vm.authorization == .denied)
        factory.fake.power(.poweredOn)
        #expect(factory.fake.startCalls.isEmpty)
        #expect(vm.isScanning == false)
        #expect(vm.widgetUpdate() == .clear)
    }

    @Test func promptSceneInactiveDefersStartUntilActive() {
        let (vm, factory, auth) = H.makeVM(auth: .undetermined, central: FakeBLECentral(powerState: .unknown))
        vm.allowAndScan()
        vm.scenePhaseChanged(isActive: false)
        auth.value = .allowed
        factory.fake.power(.poweredOn)
        #expect(factory.fake.startCalls.isEmpty)
        vm.scenePhaseChanged(isActive: true)
        #expect(factory.fake.startCalls == [true])
        #expect(vm.isScanning)
    }

    @Test func unsupportedStopsAndDoesNotCrash() {
        let (vm, factory, _) = H.makeVM(auth: .allowed, central: FakeBLECentral(powerState: .unsupported))
        #expect(vm.startScanIfAuthorized() == false)
        #expect(vm.isScanning == false)
        #expect(vm.powerState == .unsupported)
        #expect(factory.fake.startCalls.isEmpty)
        vm.allowAndScan()
        #expect(factory.fake.startCalls.isEmpty)
        #expect(factory.created == 1)
    }

    @Test func powerLossMidScanStopsAndFreezes() async throws {
        let (vm, factory, _) = H.makeVM()
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "Lamp")))
        factory.fake.power(.poweredOff)
        #expect(vm.isScanning == false)
        #expect(vm.powerState == .poweredOff)
        #expect(vm.lastScanSummary?.nearby == 1)
        #expect(vm.hasScannedThisSession)
        // Power coming back does not restart a scan on its own.
        factory.fake.power(.poweredOn)
        #expect(factory.fake.startCalls == [true])
    }

    @Test func publishingIsThrottled() async throws {
        let (vm, factory, _) = H.makeVM()
        let emissions = Box(0)
        let sink = vm.$peripherals.sink { _ in emissions.value += 1 }
        vm.startScanIfAuthorized()
        for i in 0..<50 { factory.fake.subject.send(.sighting(H.sighting(name: "Device \(i)"))) }
        #expect(vm.peripherals.isEmpty)
        try await Task.sleep(for: .milliseconds(100))
        try await H.settle(vm)
        #expect(emissions.value <= 3)
        #expect(vm.peripherals.count == 50)
        sink.cancel()
    }

    @Test func rotatedIdentifierDoesNotDuplicateRow() async throws {
        let (vm, factory, _) = H.makeVM()
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "Sonos Roam", company: H.sonos)))
        factory.fake.subject.send(.sighting(H.sighting(name: "Sonos Roam", company: H.sonos)))
        try await H.settle(vm)
        #expect(vm.peripherals.count == 1)
        #expect(vm.peripherals.first?.identifiers.count == 2)
    }

    @Test func rssiChangesDoNotReorderAndNewcomersAppend() async throws {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let (vm, factory, _) = H.makeVM(now: { t0 + 5 })
        vm.startScanIfAuthorized()
        let b = UUID(), c = UUID()
        factory.fake.subject.send(.sighting(H.sighting(b, name: "B", rssi: -50, at: t0)))
        factory.fake.subject.send(.sighting(H.sighting(c, name: "C", rssi: -70, at: t0 + 1)))
        factory.fake.subject.send(.sighting(H.sighting(name: "A", rssi: -70, at: t0 + 1)))
        try await H.settle(vm)
        #expect(vm.peripherals.map(\.displayName) == ["B", "A", "C"])
        factory.fake.subject.send(.sighting(H.sighting(c, name: "C", rssi: -30, at: t0 + 2)))
        factory.fake.subject.send(.sighting(H.sighting(b, name: "B", rssi: -95, at: t0 + 2)))
        factory.fake.subject.send(.sighting(H.sighting(name: "D", rssi: -20, at: t0 + 3)))
        try await H.settle(vm)
        #expect(vm.peripherals.map(\.displayName) == ["B", "A", "C", "D"])
    }

    // MARK: No duplicates

    @Test func rotationKeepsOneRowAndReadsTheNewestIdentifier() async throws {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let clock = Box(t0)
        let (vm, factory, _) = H.makeVM(now: { clock.value })
        factory.fake.readResult = .success(BLEDeviceInfo(manufacturer: "Sonos"))
        vm.startScanIfAuthorized()
        let a = UUID(), b = UUID(), c = UUID()
        factory.fake.subject.send(.sighting(H.sighting(a, name: "Roam", company: H.sonos, at: t0)))
        factory.fake.subject.send(.sighting(H.sighting(b, name: "Roam", company: H.sonos, at: t0 + 1)))
        factory.fake.subject.send(.sighting(H.sighting(b, company: H.sonos, at: t0 + 2)))
        factory.fake.subject.send(.sighting(H.sighting(c, company: H.sonos, at: t0 + 30)))
        factory.fake.subject.send(.sighting(H.sighting(c, name: "Roam", company: H.sonos, at: t0 + 30.5)))
        clock.value = t0 + 31
        try await H.settle(vm)
        #expect(vm.peripherals.count == 1)
        let row = try #require(vm.peripherals.first)
        #expect(row.identifiers == [a, b, c])
        #expect(row.displayName == "Roam")
        await vm.readDeviceInfo(row.id)
        #expect(factory.fake.readCalls == [c])
        vm.stopScan(reason: .user)
        #expect(vm.lastScanSummary?.nearby == 1)
    }

    @Test func simultaneousSameNameDevicesAreTwoRowsAndBothCounted() async throws {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let clock = Box(t0)
        let (vm, factory, _) = H.makeVM(now: { clock.value })
        vm.startScanIfAuthorized()
        clock.value = t0 + 4
        let a = UUID(), b = UUID()
        factory.fake.subject.send(.sighting(H.sighting(a, name: "Roam", company: H.sonos, at: t0)))
        factory.fake.subject.send(.sighting(H.sighting(b, name: "Roam", company: H.sonos, at: t0 + 0.5)))
        factory.fake.subject.send(.sighting(H.sighting(a, name: "Roam", company: H.sonos, at: t0 + 3)))
        try await H.settle(vm)
        #expect(vm.peripherals.count == 2)
        #expect(vm.seenThisScanCount == 2)
        let split = try #require(vm.peripherals.first { $0.identifiers == [b] })
        await vm.readDeviceInfo(split.id)
        #expect(factory.fake.readCalls == [b])
        vm.stopScan(reason: .user)
        #expect(vm.lastScanSummary?.nearby == 2)
    }

    @Test func splitRowHeardOnlyInAnEarlierScanIsNotCounted() async throws {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let clock = Box(t0)
        let (vm, factory, _) = H.makeVM(now: { clock.value })
        let a = UUID(), b = UUID()
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(a, name: "Roam", at: t0)))
        factory.fake.subject.send(.sighting(H.sighting(b, name: "Roam", at: t0 + 0.5)))
        try await H.settle(vm)
        vm.stopScan(reason: .user)
        #expect(vm.lastScanSummary?.nearby == 1)
        clock.value = t0 + 5
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(a, name: "Roam", at: t0 + 5)))
        try await H.settle(vm)
        #expect(vm.peripherals.count == 2)
        #expect(vm.seenThisScanCount == 1)
        vm.stopScan(reason: .user)
        #expect(vm.lastScanSummary?.nearby == 1)
    }

    @Test func splitDropsARedirectThatNoLongerFitsTheRow() async throws {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let clock = Box(t0)
        let (vm, factory, _) = H.makeVM(now: { clock.value })
        vm.startScanIfAuthorized()
        let a = UUID(), b = UUID()
        factory.fake.subject.send(.sighting(H.sighting(a, name: "Lamp", at: t0)))
        factory.fake.subject.send(.sighting(H.sighting(b, at: t0 + 30)))
        factory.fake.subject.send(.sighting(H.sighting(b, name: "Lamp", at: t0 + 30.5)))
        clock.value = t0 + 31
        try await H.settle(vm)
        #expect(vm.peripherals.count == 1)
        let survivor = try #require(vm.peripherals.first)
        let foldedID = try #require(vm.log.first { $0.peripheralID != survivor.id }?.peripheralID)
        #expect(vm.peripheral(id: foldedID)?.id == survivor.id)
        // a is heard again 3 s after b joined: two devices, so b splits off and the old redirect must go.
        clock.value = t0 + 34
        factory.fake.subject.send(.sighting(H.sighting(a, name: "Lamp", at: t0 + 33.5)))
        try await H.settle(vm)
        #expect(vm.peripherals.count == 2)
        #expect(vm.peripheral(id: foldedID) == nil)
        #expect(vm.peripheral(id: survivor.id)?.identifiers == [a])
    }

    @Test func rotateWhileSavedAttachesToExactlyOneRow() async throws {
        let store = H.tempStore()
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let (first, firstFactory, _) = H.makeVM(store: store, now: { t0 })
        first.startScanIfAuthorized()
        firstFactory.fake.subject.send(.sighting(H.sighting(name: "Lamp", at: t0)))
        try await H.settle(first)
        first.addToDevices(try #require(first.peripherals.first).id)
        let saved = try #require(first.saved.first)

        // Rotation: one device moves from a to b.
        let clock = Box(t0 + 100)
        let (vm, factory, _) = H.makeVM(store: store, now: { clock.value })
        vm.startScanIfAuthorized()
        let a = UUID(), b = UUID()
        factory.fake.subject.send(.sighting(H.sighting(a, name: "Lamp", at: t0 + 100)))
        factory.fake.subject.send(.sighting(H.sighting(b, at: t0 + 130)))
        factory.fake.subject.send(.sighting(H.sighting(b, name: "Lamp", at: t0 + 130.5)))
        clock.value = t0 + 131
        try await H.settle(vm)
        #expect(vm.peripherals.count == 1)
        #expect(vm.peripherals.filter { $0.savedID == saved.id }.count == 1)

        // Two devices at once: the saved entry stays on one row.
        let (both, bothFactory, _) = H.makeVM(store: store, now: { t0 + 204 })
        both.startScanIfAuthorized()
        let x = UUID(), y = UUID()
        bothFactory.fake.subject.send(.sighting(H.sighting(x, name: "Lamp", at: t0 + 200)))
        bothFactory.fake.subject.send(.sighting(H.sighting(y, name: "Lamp", at: t0 + 200.5)))
        bothFactory.fake.subject.send(.sighting(H.sighting(x, name: "Lamp", at: t0 + 203)))
        try await H.settle(both)
        #expect(both.peripherals.count == 2)
        #expect(both.peripherals.filter { $0.savedID == saved.id }.count == 1)
        let plan = DevicesListPlan.make(filter: .bluetooth, devices: [], peripherals: both.peripherals, saved: both.saved, now: t0 + 204)
        #expect(!plan.sections.flatMap(\.rows).contains(.saved(try #require(both.saved.first))))
    }

    @Test func quietRowAbsorbsSuccessorOnTick() async throws {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let clock = Box(t0 + 3.5)
        let (vm, factory, _) = H.makeVM(now: { clock.value })
        vm.startScanIfAuthorized()
        let a = UUID(), b = UUID(), c = UUID()
        factory.fake.subject.send(.sighting(H.sighting(a, name: "Roam", at: t0)))
        factory.fake.subject.send(.sighting(H.sighting(b, name: "Roam", at: t0)))
        factory.fake.subject.send(.sighting(H.sighting(a, name: "Roam", at: t0 + 3)))
        factory.fake.subject.send(.sighting(H.sighting(c, name: "Roam", at: t0 + 3.2)))
        try await H.settle(vm)
        #expect(vm.peripherals.count == 3)
        let rowA = try #require(vm.peripherals.first { $0.identifiers == [a] })
        let rowC = try #require(vm.peripherals.first { $0.identifiers == [c] })
        clock.value = t0 + 14
        factory.fake.subject.send(.sighting(H.sighting(b, name: "Roam", at: t0 + 14)))
        factory.fake.subject.send(.sighting(H.sighting(c, name: "Roam", at: t0 + 14)))
        try await H.settle(vm)
        #expect(vm.peripherals.count == 2)
        #expect(vm.peripheral(id: rowC.id)?.id == rowA.id)
        #expect(vm.seenThisScanCount == 2)
        factory.fake.readResult = .success(BLEDeviceInfo(manufacturer: "Sonos"))
        await vm.readDeviceInfo(rowA.id)
        #expect(factory.fake.readCalls == [c])
    }

    @Test func removeFromListDropsOnlyUnsavedRows() async throws {
        let (vm, factory, _) = H.makeVM()
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "Lamp")))
        factory.fake.subject.send(.sighting(H.sighting(name: "Desk")))
        try await H.settle(vm)
        let lamp = try #require(vm.peripherals.first { $0.displayName == "Lamp" })
        let desk = try #require(vm.peripherals.first { $0.displayName == "Desk" })
        vm.addToDevices(desk.id)
        vm.removeFromList(desk.id)
        #expect(vm.peripherals.contains { $0.id == desk.id })
        vm.removeFromList(lamp.id)
        #expect(!vm.peripherals.contains { $0.id == lamp.id })
    }

    @Test func findMyBeaconIsNeverConnectedTo() async throws {
        let (vm, factory, _) = H.makeVM()
        vm.startScanIfAuthorized()
        let fields = BLEAdvertisementFields(manufacturerData: Data([0x4C, 0x00, 0x12, 0x02, 0x00, 0x00]), isConnectable: true)
        factory.fake.subject.send(.sighting(BLESighting(identifier: UUID(), fields: fields, rssi: -60, at: Date())))
        try await H.settle(vm)
        let row = try #require(vm.peripherals.first)
        #expect(row.parsed.kind == .findMy)
        await vm.readDeviceInfo(row.id)
        #expect(vm.peripheral(id: row.id)?.readState == .failed(.notOffered))
        #expect(factory.fake.readCalls.isEmpty)
    }

    @Test func secondReadIsBusyAndLeavesTheFirstRunning() async throws {
        let (vm, factory, _) = H.makeVM()
        factory.fake.readDelay = .seconds(30)
        factory.fake.readResult = .success(BLEDeviceInfo(manufacturer: "Acme"))
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "Lamp")))
        factory.fake.subject.send(.sighting(H.sighting(name: "Desk")))
        try await H.settle(vm)
        let lamp = try #require(vm.peripherals.first { $0.displayName == "Lamp" })
        let desk = try #require(vm.peripherals.first { $0.displayName == "Desk" })
        let read = Task { await vm.readDeviceInfo(lamp.id) }
        // The fake records the call from inside the read task, which may start a moment after `.reading` publishes.
        try await H.waitUntil { vm.peripheral(id: lamp.id)?.readState == .reading && factory.fake.readCalls.count == 1 }
        await vm.readDeviceInfo(desk.id)
        #expect(vm.peripheral(id: desk.id)?.readState == .failed(.busy))
        #expect(vm.peripheral(id: lamp.id)?.readState == .reading)
        #expect(factory.fake.readCalls.count == 1)
        #expect(BluetoothCardView.failureText(.busy) == "Another read is running.")
        vm.scenePhaseChanged(isActive: false)
        await read.value
        #expect(vm.peripheral(id: lamp.id)?.readState == .failed(.timedOut))
        #expect(factory.fake.cancelledReads == 1)
    }

    @Test func expiredSavedRowIsKeptAfterTick() async throws {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let clock = Box(t0)
        let (vm, factory, _) = H.makeVM(now: { clock.value })
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "Sonos Roam", company: H.sonos, at: t0)))
        try await H.settle(vm)
        vm.addToDevices(try #require(vm.peripherals.first).id)
        vm.stopScan(reason: .user)
        clock.value = t0 + 400
        vm.scenePhaseChanged(isActive: false)
        vm.scenePhaseChanged(isActive: true)
        #expect(vm.peripherals.count == 1)
        #expect(vm.hasScannedThisSession)
    }

    @Test func timeoutEndsScanAndFreezesSummary() async throws {
        let (vm, factory, _) = H.makeVM()
        vm.startScanIfAuthorized(duration: 0.05)
        factory.fake.subject.send(.sighting(H.sighting(name: "One")))
        factory.fake.subject.send(.sighting(H.sighting(name: "Two")))
        try await H.waitUntil { !vm.isScanning }
        #expect(vm.isScanning == false)
        #expect(vm.lastScanSummary?.nearby == 2)
        #expect(vm.hasScannedThisSession)
        #expect(factory.fake.stopCalls == 1)
    }

    @Test func sceneInactiveStopsAndReturnMarksStale() async throws {
        let (vm, factory, _) = H.makeVM()
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "One")))
        factory.fake.subject.send(.sighting(H.sighting(name: "Two")))
        try await H.settle(vm)
        vm.scenePhaseChanged(isActive: false)
        #expect(factory.fake.stopCalls == 1)
        #expect(vm.isScanning == false)
        #expect(vm.lastScanSummary?.nearby == 2)
        vm.scenePhaseChanged(isActive: true)
        #expect(vm.peripherals.count == 2)
        #expect(vm.peripherals.allSatisfy { $0.markedStale })
        #expect(vm.peripherals.allSatisfy { $0.lifecycle(now: Date()) == .dim })
        // Returning to the foreground does not start a scan by itself.
        #expect(factory.fake.startCalls == [true])
    }

    @Test func pausedTimeDoesNotAge() {
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let clock = Box(t0)
        let (vm, factory, _) = H.makeVM(now: { clock.value })
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "Lamp", at: t0)))
        clock.value = t0 + 10
        vm.scenePhaseChanged(isActive: false)
        clock.value = t0 + 1000
        vm.scenePhaseChanged(isActive: true)
        #expect(vm.peripherals.count == 1)
        guard let p = vm.peripherals.first else { return }
        #expect(p.markedStale)
        #expect(p.lifecycle(now: t0 + 1010) == .dim)
        #expect(p.lastSeen == t0)
    }

    @Test func addToDevicesSavesStableFieldsAndMarksRow() async throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ble-vm-\(UUID().uuidString)/saved.json")
        let store = BLEDeviceStore(fileURL: url)
        // Whole seconds, because the store writes ISO 8601 dates without fractions.
        let t = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))
        let (vm, factory, _) = H.makeVM(store: store, now: { t })
        vm.startScanIfAuthorized()
        let identifier = UUID()
        factory.fake.subject.send(.sighting(H.sighting(identifier, name: "Lamp", at: t)))
        try await H.settle(vm)
        let row = try #require(vm.peripherals.first)
        vm.addToDevices(row.id)
        #expect(vm.saved.count == 1)
        let saved = try #require(vm.saved.first)
        #expect(saved.name == "Lamp")
        #expect(saved.companyID == H.apple)
        #expect(vm.peripherals.first?.savedID == saved.id)
        #expect(vm.peripheral(id: row.id)?.savedID == saved.id)
        // Adding twice keeps one entry; the CoreBluetooth identifier never reaches the file.
        vm.addToDevices(row.id)
        #expect(vm.saved.count == 1)
        let reloaded = BLEDeviceStore(fileURL: url)
        reloaded.load()
        #expect(reloaded.devices == vm.saved)
        let text = try String(contentsOf: url, encoding: .utf8)
        #expect(!text.contains(identifier.uuidString))
    }

    @Test func forgetAndMergeSaved() async throws {
        let (vm, factory, _) = H.makeVM()
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "Lamp")))
        factory.fake.subject.send(.sighting(H.sighting(name: "Desk", rssi: -80)))
        try await H.settle(vm)
        let lamp = try #require(vm.peripherals.first { $0.displayName == "Lamp" })
        let desk = try #require(vm.peripherals.first { $0.displayName == "Desk" })
        vm.addToDevices(lamp.id)
        vm.addToDevices(desk.id)
        let lampSaved = try #require(vm.peripheral(id: lamp.id)?.savedID)
        let deskSaved = try #require(vm.peripheral(id: desk.id)?.savedID)
        vm.mergeSaved(deskSaved, into: lampSaved)
        #expect(vm.saved.map(\.id) == [lampSaved])
        #expect(vm.peripheral(id: desk.id)?.savedID == lampSaved)
        vm.forgetSaved(lampSaved)
        #expect(vm.saved.isEmpty)
        #expect(vm.peripherals.allSatisfy { $0.savedID == nil })
    }

    @Test func savedEntryReattachesByFingerprint() async throws {
        let store = H.tempStore()
        let (first, firstFactory, _) = H.makeVM(store: store)
        first.startScanIfAuthorized()
        firstFactory.fake.subject.send(.sighting(H.sighting(name: "Lamp")))
        try await H.settle(first)
        first.addToDevices(try #require(first.peripherals.first).id)
        let saved = try #require(first.saved.first)

        let later = Date().addingTimeInterval(3600)
        let (vm, factory, _) = H.makeVM(store: store, now: { later })
        #expect(vm.saved.map(\.id) == [saved.id])
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "Lamp", at: later)))
        try await H.settle(vm)
        #expect(vm.peripherals.first?.savedID == saved.id)
        #expect(vm.saved.first?.lastSeenAt == later)
    }

    @Test func readDeviceInfoSetsResultAndUsesTimeout() async throws {
        let (vm, factory, _) = H.makeVM()
        let info = BLEDeviceInfo(manufacturer: "Acme", model: "Lamp 2", firmware: "1.0", batteryPercent: 80)
        factory.fake.readResult = .success(info)
        vm.startScanIfAuthorized()
        let identifier = UUID()
        factory.fake.subject.send(.sighting(H.sighting(identifier, name: "Lamp")))
        try await H.settle(vm)
        let row = try #require(vm.peripherals.first)
        await vm.readDeviceInfo(row.id)
        #expect(vm.peripheral(id: row.id)?.readState == .done)
        #expect(vm.peripheral(id: row.id)?.deviceInfo == info)
        #expect(factory.fake.readCalls == [identifier])
        #expect(factory.fake.readTimeouts == [BluetoothViewModel.readTimeout])
        #expect(BluetoothViewModel.readTimeout == .seconds(5))

        factory.fake.readResult = .failure(.timedOut)
        await vm.readDeviceInfo(row.id)
        #expect(vm.peripheral(id: row.id)?.readState == .failed(.timedOut))
    }

    @Test func readWhilePoweredOffFailsWithoutConnecting() async throws {
        let (vm, factory, _) = H.makeVM()
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "Lamp")))
        try await H.settle(vm)
        let row = try #require(vm.peripherals.first)
        factory.fake.power(.poweredOff)
        await vm.readDeviceInfo(row.id)
        #expect(vm.peripheral(id: row.id)?.readState == .failed(.poweredOff))
        #expect(factory.fake.readCalls.isEmpty)
    }

    @Test func readShowsReadingWhileInFlight() async throws {
        let (vm, factory, _) = H.makeVM()
        factory.fake.readDelay = .milliseconds(100)
        factory.fake.readResult = .success(BLEDeviceInfo(manufacturer: "Acme"))
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "Lamp")))
        try await H.settle(vm)
        let row = try #require(vm.peripherals.first)
        let read = Task { await vm.readDeviceInfo(row.id) }
        try await H.waitUntil { vm.peripheral(id: row.id)?.readState == .reading }
        #expect(vm.peripheral(id: row.id)?.readState == .reading)
        await read.value
        #expect(vm.peripheral(id: row.id)?.readState == .done)
    }

    @Test func readEndsWhenSceneGoesInactive() async throws {
        let (vm, factory, _) = H.makeVM()
        // A 30 s read against a 10 s bound, so a loaded parallel run cannot blur the result.
        factory.fake.readDelay = .seconds(30)
        factory.fake.readResult = .success(BLEDeviceInfo(manufacturer: "Acme"))
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "Lamp")))
        try await H.settle(vm)
        let row = try #require(vm.peripherals.first)
        let read = Task { await vm.readDeviceInfo(row.id) }
        try await H.waitUntil { vm.peripheral(id: row.id)?.readState == .reading }
        let clock = ContinuousClock()
        let start = clock.now
        vm.scenePhaseChanged(isActive: false)
        await read.value
        #expect(clock.now - start < .seconds(10))
        #expect(vm.peripheral(id: row.id)?.readState == .failed(.timedOut))
        #expect(factory.fake.cancelledReads == 1)
    }

    @Test func readEndsWhenPowerIsLost() async throws {
        let (vm, factory, _) = H.makeVM()
        factory.fake.readDelay = .seconds(1)
        factory.fake.readResult = .success(BLEDeviceInfo(manufacturer: "Acme"))
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "Lamp")))
        try await H.settle(vm)
        let row = try #require(vm.peripherals.first)
        let read = Task { await vm.readDeviceInfo(row.id) }
        try await H.waitUntil { vm.peripheral(id: row.id)?.readState == .reading }
        factory.fake.power(.poweredOff)
        await read.value
        #expect(vm.peripheral(id: row.id)?.readState == .failed(.timedOut))
        #expect(factory.fake.cancelledReads == 1)
    }

    @Test func rssi127DoesNotSortFirstOrReadNear() async throws {
        let (vm, factory, _) = H.makeVM()
        vm.startScanIfAuthorized()
        let existing = UUID()
        let base = Date()
        factory.fake.subject.send(.sighting(H.sighting(existing, name: "Known", rssi: -70, at: base)))
        factory.fake.subject.send(.sighting(H.sighting(existing, name: "Known", rssi: 127, at: base + 0.1)))
        factory.fake.subject.send(.sighting(H.sighting(name: "Blank", rssi: 127, at: base + 0.2)))
        factory.fake.subject.send(.sighting(H.sighting(name: "Far", rssi: -95, at: base + 0.3)))
        try await H.settle(vm)
        #expect(vm.peripherals.map(\.displayName) == ["Known", "Blank", "Far"])
        let known = try #require(vm.peripherals.first { $0.displayName == "Known" })
        #expect(known.rssi == -70)
        #expect(known.rssiHistory.samples == [-70])
        let blank = try #require(vm.peripherals.first { $0.displayName == "Blank" })
        #expect(blank.rssi == BLEPeripheralSet.noReadingFloor)
        #expect(blank.rssiHistory.samples.isEmpty)
        #expect(blank.distance == .far)
        // The log keeps the raw value.
        #expect(vm.log.contains { $0.rssi == 127 })
    }

    @Test func logCapsAndClears() async throws {
        let (vm, factory, _) = H.makeVM()
        vm.startScanIfAuthorized()
        let identifier = UUID()
        let base = Date()
        let total = BluetoothViewModel.logCapacity + 7
        for i in 0..<total {
            factory.fake.subject.send(.sighting(H.sighting(identifier, rssi: -50 - i % 30, at: base.addingTimeInterval(Double(i) / 1000))))
        }
        try await H.settle(vm)
        #expect(vm.log.count == BluetoothViewModel.logCapacity)
        #expect(vm.log.first?.at == base.addingTimeInterval(7.0 / 1000))
        #expect(vm.log.last?.at == base.addingTimeInterval(Double(total - 1) / 1000))
        #expect(vm.log.allSatisfy { $0.peripheralID == vm.peripherals.first?.id })
        vm.clearLog()
        #expect(vm.log.isEmpty)
    }

    @Test func nearbyCountSkipsExpiredRows() async throws {
        let t0 = Date()
        let clock = Box(t0)
        let (vm, factory, _) = H.makeVM(now: { clock.value })
        vm.startScanIfAuthorized()
        factory.fake.subject.send(.sighting(H.sighting(name: "Old", at: t0 - 400)))
        factory.fake.subject.send(.sighting(H.sighting(name: "New", at: t0)))
        vm.stopScan(reason: .user)
        #expect(vm.nearbyCount == 1)
    }
}
