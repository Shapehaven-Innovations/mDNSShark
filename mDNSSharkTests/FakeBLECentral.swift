import Foundation
import Combine
@testable import mDNSShark

/// Drives `BluetoothViewModel` without CoreBluetoothCentral; events go out through `subject`.
@MainActor
final class FakeBLECentral: BLECentral {
    let subject = PassthroughSubject<BLECentralEvent, Never>()
    var powerState: BLEPowerState
    var startCalls: [Bool] = []
    var stopCalls = 0
    var readResult: Result<BLEDeviceInfo, BLEReadError> = .failure(.notFound)
    var readCalls: [UUID] = []
    var readTimeouts: [Duration] = []
    var readDelay: Duration = .zero
    /// Reads that ended because their task was cancelled, standing in for the real central's disconnect.
    private(set) var cancelledReads = 0

    init(powerState: BLEPowerState = .poweredOn) { self.powerState = powerState }

    var events: AnyPublisher<BLECentralEvent, Never> { subject.eraseToAnyPublisher() }

    func startScan(allowDuplicates: Bool) { startCalls.append(allowDuplicates) }
    func stopScan() { stopCalls += 1 }

    func readDeviceInformation(identifier: UUID, timeout: Duration) async -> Result<BLEDeviceInfo, BLEReadError> {
        readCalls.append(identifier)
        readTimeouts.append(timeout)
        if readDelay > .zero { try? await Task.sleep(for: readDelay) }
        if Task.isCancelled {
            cancelledReads += 1
            return .failure(.timedOut)
        }
        return readResult
    }

    /// Sends a power change the way CoreBluetoothCentral does: state first, then the event.
    func power(_ state: BLEPowerState) {
        powerState = state
        subject.send(.power(state))
    }
}

/// Counts how many centrals the view model asked for, so tests can prove none was created.
@MainActor
final class CentralFactory {
    let fake: FakeBLECentral
    private(set) var created = 0

    init(_ fake: FakeBLECentral) { self.fake = fake }

    func make() -> any BLECentral {
        created += 1
        return fake
    }
}

/// A mutable value tests can change behind an injected closure.
final class Box<T> {
    var value: T
    init(_ value: T) { self.value = value }
}
