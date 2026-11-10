import Foundation

/// A last-resort kind for advertisements that carry only a company ID, for companies whose Bluetooth products are nearly all one kind.
public enum BLECompanyKindHints {
    private static let wearable = (kind: BLEKind.wearable, reason: "Advertised company mostly makes wearables")
    private static let audio = (kind: BLEKind.audio, reason: "Advertised company mostly makes audio products")
    private static let health = (kind: BLEKind.health, reason: "Advertised company mostly makes health devices")

    private static let hints: [UInt16: (kind: BLEKind, reason: String)] = [
        135: wearable,  // Garmin
        107: wearable,  // Polar Electro
        343: wearable,  // Huami
        158: audio,     // Bose
        87: audio,      // Harman
        1172: audio,    // Sennheiser
        208: health,    // Dexcom
        103: health,    // GN Hearing
        137: health,    // GN Hearing
    ]

    public static func hint(for companyID: UInt16) -> (kind: BLEKind, reason: String)? { hints[companyID] }
}
