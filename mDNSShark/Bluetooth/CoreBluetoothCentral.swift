import Foundation
import Combine
import CoreBluetooth
import DeviceFingerprint

/// The GATT services and characteristics the user-started read asks for.
private enum GATT {
    static let deviceInformation = "180A"
    static let battery = "180F"
    static let manufacturerName = "2A29"
    static let modelNumber = "2A24"
    static let firmwareRevision = "2A26"
    static let batteryLevel = "2A19"

    static func characteristics(for service: String) -> [String] {
        switch service {
        case deviceInformation: return [manufacturerName, modelNumber, firmwareRevision]
        case battery: return [batteryLevel]
        default: return []
        }
    }
}

/// One in-flight Device Information read. Holds the peripheral strongly until the read ends.
@MainActor
private final class GATTRead {
    let peripheral: CBPeripheral
    var continuation: CheckedContinuation<Result<BLEDeviceInfo, BLEReadError>, Never>?
    var info = BLEDeviceInfo()
    var pendingServices = 0
    var pendingReads = 0

    init(peripheral: CBPeripheral) { self.peripheral = peripheral }
}

/// The real central. Creating it creates the `CBCentralManager`, which is what shows the system prompt.
@MainActor
final class CoreBluetoothCentral: NSObject, BLECentral, CBCentralManagerDelegate, CBPeripheralDelegate {
    private let subject = PassthroughSubject<BLECentralEvent, Never>()
    private var manager: CBCentralManager?
    private var read: GATTRead?
    private(set) var powerState: BLEPowerState = .unknown

    var events: AnyPublisher<BLECentralEvent, Never> { subject.eraseToAnyPublisher() }

    override init() {
        super.init()
        manager = CBCentralManager(delegate: self, queue: .main, options: [CBCentralManagerOptionShowPowerAlertKey: false])
    }

    func startScan(allowDuplicates: Bool) {
        guard let manager, manager.state == .poweredOn else { return }
        manager.scanForPeripherals(withServices: nil, options: [CBCentralManagerScanOptionAllowDuplicatesKey: allowDuplicates])
    }

    func stopScan() {
        guard let manager, manager.state == .poweredOn, manager.isScanning else { return }
        manager.stopScan()
    }

    func readDeviceInformation(identifier: UUID, timeout: Duration) async -> Result<BLEDeviceInfo, BLEReadError> {
        guard let manager, manager.state == .poweredOn else { return .failure(.poweredOff) }
        guard read == nil else { return .failure(.connectFailed) }
        guard let peripheral = manager.retrievePeripherals(withIdentifiers: [identifier]).first else { return .failure(.notFound) }
        let current = GATTRead(peripheral: peripheral)
        read = current
        peripheral.delegate = self
        let timer = Task { [weak self] in
            try? await Task.sleep(for: timeout)
            guard !Task.isCancelled else { return }
            self?.finish(current, .failure(.timedOut))
        }
        // Every exit path (success, timeout, error, cancellation) disconnects.
        defer {
            timer.cancel()
            if manager.state == .poweredOn { manager.cancelPeripheralConnection(peripheral) }
            peripheral.delegate = nil
            if read === current { read = nil }
        }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                current.continuation = continuation
                manager.connect(peripheral)
            }
        } onCancel: {
            Task { @MainActor [weak self] in self?.finish(current, .failure(.timedOut)) }
        }
    }

    /// Maps CoreBluetooth's advertisement dictionary; values of the wrong type are dropped.
    nonisolated static func sighting(identifier: UUID, advertisement: [String: Any], rssi: NSNumber, at: Date) -> BLESighting {
        let uuids = (advertisement[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID] ?? [])
            + (advertisement[CBAdvertisementDataOverflowServiceUUIDsKey] as? [CBUUID] ?? [])
        var serviceData: [String: Data] = [:]
        if let raw = advertisement[CBAdvertisementDataServiceDataKey] as? [CBUUID: Data] {
            for (key, value) in raw { serviceData[key.uuidString] = value }
        }
        let fields = BLEAdvertisementFields(
            localName: advertisement[CBAdvertisementDataLocalNameKey] as? String,
            manufacturerData: advertisement[CBAdvertisementDataManufacturerDataKey] as? Data,
            serviceUUIDs: uuids.map(\.uuidString),
            serviceData: serviceData,
            txPower: (advertisement[CBAdvertisementDataTxPowerLevelKey] as? NSNumber)?.intValue,
            isConnectable: (advertisement[CBAdvertisementDataIsConnectable] as? NSNumber)?.boolValue)
        return BLESighting(identifier: identifier, fields: fields, rssi: rssi.intValue, at: at)
    }

    /// Stores one characteristic value; strings are sanitized like advertised names, battery outside 0...100 is dropped.
    nonisolated static func apply(_ value: Data, characteristic uuid: String, to info: inout BLEDeviceInfo) {
        func text() -> String? { BLEDisplayName.sanitized(String(decoding: value.prefix(512), as: UTF8.self)) }
        switch uuid {
        case GATT.manufacturerName: info.manufacturer = text()
        case GATT.modelNumber: info.model = text()
        case GATT.firmwareRevision: info.firmware = text()
        case GATT.batteryLevel:
            if let level = value.first, level <= 100 { info.batteryPercent = Int(level) }
        default: break
        }
    }

    private func finish(_ r: GATTRead, _ result: Result<BLEDeviceInfo, BLEReadError>) {
        guard let continuation = r.continuation else { return }
        r.continuation = nil
        continuation.resume(returning: result)
    }

    private func finishIfDone(_ r: GATTRead) {
        guard r.pendingServices == 0, r.pendingReads == 0 else { return }
        finish(r, r.info.isEmpty ? .failure(.noServices) : .success(r.info))
    }

    /// The in-flight read for this peripheral, if any.
    private func activeRead(_ id: UUID) -> GATTRead? {
        guard let r = read, r.peripheral.identifier == id else { return nil }
        return r
    }

    // MARK: CBCentralManagerDelegate (delivered on the main queue)

    nonisolated func centralManagerDidUpdateState(_ central: CBCentralManager) {
        let state = BLEPowerState(central.state)
        MainActor.assumeIsolated {
            powerState = state
            if state != .poweredOn, let r = read { finish(r, .failure(.poweredOff)) }
            subject.send(.power(state))
        }
    }

    nonisolated func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                                    advertisementData: [String: Any], rssi RSSI: NSNumber) {
        let s = Self.sighting(identifier: peripheral.identifier, advertisement: advertisementData, rssi: RSSI, at: Date())
        MainActor.assumeIsolated { subject.send(.sighting(s)) }
    }

    nonisolated func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        let id = peripheral.identifier
        MainActor.assumeIsolated {
            guard let r = activeRead(id) else { return }
            r.peripheral.discoverServices([CBUUID(string: GATT.deviceInformation), CBUUID(string: GATT.battery)])
        }
    }

    nonisolated func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        let id = peripheral.identifier
        MainActor.assumeIsolated {
            guard let r = activeRead(id) else { return }
            finish(r, .failure(.connectFailed))
        }
    }

    nonisolated func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        let id = peripheral.identifier
        MainActor.assumeIsolated {
            guard let r = activeRead(id) else { return }
            finish(r, r.info.isEmpty ? .failure(.connectFailed) : .success(r.info))
        }
    }

    // MARK: CBPeripheralDelegate

    nonisolated func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        let id = peripheral.identifier
        let failed = error != nil
        MainActor.assumeIsolated {
            guard let r = activeRead(id) else { return }
            let services = failed ? [] : (r.peripheral.services ?? [])
            for service in services {
                let wanted = GATT.characteristics(for: service.uuid.uuidString)
                guard !wanted.isEmpty else { continue }
                r.pendingServices += 1
                r.peripheral.discoverCharacteristics(wanted.map { CBUUID(string: $0) }, for: service)
            }
            finishIfDone(r)
        }
    }

    nonisolated func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        let id = peripheral.identifier
        let serviceUUID = service.uuid.uuidString
        let failed = error != nil
        MainActor.assumeIsolated {
            guard let r = activeRead(id) else { return }
            r.pendingServices = max(0, r.pendingServices - 1)
            let wanted = GATT.characteristics(for: serviceUUID)
            let held = r.peripheral.services?.first { $0.uuid.uuidString == serviceUUID }
            for characteristic in failed ? [] : (held?.characteristics ?? [])
            where characteristic.properties.contains(.read) && wanted.contains(characteristic.uuid.uuidString) {
                r.pendingReads += 1
                r.peripheral.readValue(for: characteristic)
            }
            finishIfDone(r)
        }
    }

    nonisolated func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        let id = peripheral.identifier
        let uuid = characteristic.uuid.uuidString
        let value = error == nil ? characteristic.value : nil
        MainActor.assumeIsolated {
            guard let r = activeRead(id) else { return }
            r.pendingReads = max(0, r.pendingReads - 1)
            if let value { Self.apply(value, characteristic: uuid, to: &r.info) }
            finishIfDone(r)
        }
    }
}
