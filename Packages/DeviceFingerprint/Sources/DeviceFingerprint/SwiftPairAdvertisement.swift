import Foundation

/// Microsoft Swift Pair beacon in manufacturer data for company 0x0006.
public struct SwiftPairAdvertisement: Equatable, Sendable {
    public var scenario: UInt8
    public var displayName: String?
    public static let companyID: UInt16 = 0x0006

    public init(scenario: UInt8, displayName: String?) {
        self.scenario = scenario
        self.displayName = displayName
    }

    /// Payload: beacon ID 0x03, scenario, reserved RSSI byte, then a UTF-8 display name.
    public static func parse(manufacturerPayload: Data) -> SwiftPairAdvertisement? {
        let b = Array(manufacturerPayload)
        guard b.count >= 3, b[0] == 0x03 else { return nil }
        let name = String(decoding: b.dropFirst(3), as: UTF8.self)
        return SwiftPairAdvertisement(scenario: b[1], displayName: BLEDisplayName.sanitized(name))
    }
}
