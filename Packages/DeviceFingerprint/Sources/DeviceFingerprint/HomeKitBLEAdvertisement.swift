import Foundation

/// HomeKit accessory advertisement carried in Apple Continuity type 0x06.
public struct HomeKitBLEAdvertisement: Equatable, Sendable {
    public var category: Int
    public var pairingEnabled: Bool
    public var categoryKind: DeviceKind?

    public init(category: Int, pairingEnabled: Bool, categoryKind: DeviceKind?) {
        self.category = category
        self.pairingEnabled = pairingEnabled
        self.categoryKind = categoryKind
    }

    /// Needs 14 bytes: subtype and length, status flags, 6 device ID bytes (not kept), category LE, GSN, config number, compat version.
    public static func parse(continuityPayload: Data) -> HomeKitBLEAdvertisement? {
        let b = Array(continuityPayload)
        guard b.count >= 14 else { return nil }
        let category = Int(b[8]) | Int(b[9]) << 8
        return HomeKitBLEAdvertisement(category: category, pairingEnabled: b[1] & 0x01 != 0, categoryKind: BonjourTypeCatalog.hapCategoryKind(category))
    }
}
