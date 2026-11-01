import Foundation

/// A coarse kind a Bonjour type or TXT value can imply. Anything finer is shown literally, not as a kind.
public enum DeviceKind: String, CaseIterable, Sendable {
    case camera, audio, tv, smartHome, nas, network, printer, computer
}
