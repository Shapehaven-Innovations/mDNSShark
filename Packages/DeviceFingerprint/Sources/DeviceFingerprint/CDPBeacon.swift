import Foundation

/// Microsoft Connected Devices Platform beacon (MS-CDP) in manufacturer data for company 0x0006.
/// The salt and hash change with the address, so only the device type and flags identify anything.
public struct CDPBeacon: Equatable, Sendable {
    public var deviceType: UInt8
    public var nearbySharingEveryone: Bool

    public init(deviceType: UInt8, nearbySharingEveryone: Bool) {
        self.deviceType = deviceType
        self.nearbySharingEveryone = nearbySharingEveryone
    }

    /// Payload: scenario 0x01, version and device type, version and flags, flags and status, 4 byte salt, 19 byte hash.
    public static func parse(manufacturerPayload: Data) -> CDPBeacon? {
        let b = Array(manufacturerPayload)
        guard b.count >= 4, b[0] == 0x01 else { return nil }
        return CDPBeacon(deviceType: b[1] & 0x1F, nearbySharingEveryone: b[2] & 0x1F == 0x01)
    }

    /// Device types named by MS-CDP; nil for a value the spec does not list.
    public var deviceTypeLabel: String? {
        switch deviceType {
        case 1: return "Xbox One"
        case 6: return "iPhone"
        case 7: return "iPad"
        case 8: return "Android device"
        case 9: return "Windows desktop"
        case 11: return "Windows phone"
        case 12: return "Linux device"
        case 13: return "Windows IoT"
        case 14: return "Surface Hub"
        case 15: return "Windows laptop"
        case 16: return "Windows tablet"
        default: return nil
        }
    }
}
