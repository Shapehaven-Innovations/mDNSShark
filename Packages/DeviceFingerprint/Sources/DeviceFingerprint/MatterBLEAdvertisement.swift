import Foundation

/// Matter commissionable advertisement carried in service data for 0xFFF6.
public struct MatterBLEAdvertisement: Equatable, Sendable {
    public var discriminator: UInt16
    public var vendorID: UInt16
    public var productID: UInt16
    public static let serviceUUID = "FFF6"

    public init(discriminator: UInt16, vendorID: UInt16, productID: UInt16) {
        self.discriminator = discriminator
        self.vendorID = vendorID
        self.productID = productID
    }

    /// Needs 8 bytes and opcode 0: opcode, discriminator (low 12 bits), vendor ID, product ID, flags.
    public static func parse(serviceData: Data) -> MatterBLEAdvertisement? {
        let b = Array(serviceData)
        guard b.count >= 8, b[0] == 0x00 else { return nil }
        let disc = (UInt16(b[1]) | UInt16(b[2]) << 8) & 0x0FFF
        return MatterBLEAdvertisement(discriminator: disc,
                                      vendorID: UInt16(b[3]) | UInt16(b[4]) << 8,
                                      productID: UInt16(b[5]) | UInt16(b[6]) << 8)
    }
}
