import Foundation
import Combine
import CoreBluetooth

enum BLEAuthorization: Equatable {
    case undetermined, allowed, denied, restricted

    /// Reads the `CBManager.authorization` class property, which never shows the permission prompt.
    static func current() -> BLEAuthorization {
        switch CBManager.authorization {
        case .allowedAlways: return .allowed
        case .notDetermined: return .undetermined
        case .restricted: return .restricted
        case .denied: return .denied
        @unknown default: return .denied
        }
    }
}

enum BLEPowerState: Equatable {
    case unknown, resetting, unsupported, poweredOff, poweredOn

    /// `.unauthorized` maps to `.unknown` because authorization is tracked on its own through `BLEAuthorization`.
    init(_ state: CBManagerState) {
        switch state {
        case .poweredOn: self = .poweredOn
        case .poweredOff: self = .poweredOff
        case .unsupported: self = .unsupported
        case .resetting: self = .resetting
        case .unknown, .unauthorized: self = .unknown
        @unknown default: self = .unknown
        }
    }
}

enum BLECentralEvent: Equatable {
    case power(BLEPowerState)
    case sighting(BLESighting)
}

/// The seam between the view model and CoreBluetooth, so tests can drive scans with a fake.
@MainActor
protocol BLECentral: AnyObject {
    var events: AnyPublisher<BLECentralEvent, Never> { get }
    var powerState: BLEPowerState { get }
    func startScan(allowDuplicates: Bool)
    func stopScan()
    /// Connects, reads Device Information and Battery, and disconnects on every exit path.
    func readDeviceInformation(identifier: UUID, timeout: Duration) async -> Result<BLEDeviceInfo, BLEReadError>
}
