import Foundation

/// The decoded fields of one Bluetooth LE advertisement, as the OS reports them.
public struct BLEAdvertisementFields: Equatable, Sendable {
    public var localName: String?
    public var manufacturerData: Data?
    public var serviceUUIDs: [String]
    public var serviceData: [String: Data]
    public var txPower: Int?
    public var isConnectable: Bool?

    public init(localName: String? = nil, manufacturerData: Data? = nil, serviceUUIDs: [String] = [], serviceData: [String: Data] = [:], txPower: Int? = nil, isConnectable: Bool? = nil) {
        self.localName = localName
        self.manufacturerData = manufacturerData
        self.serviceUUIDs = serviceUUIDs
        self.serviceData = serviceData
        self.txPower = txPower
        self.isConnectable = isConnectable
    }

    /// The first two manufacturer data bytes, little endian.
    public var companyID: UInt16? {
        guard let d = manufacturerData, d.count >= 2 else { return nil }
        let b = Array(d.prefix(2))
        return UInt16(b[0]) | UInt16(b[1]) << 8
    }

    /// The manufacturer data after the company ID.
    public var manufacturerPayload: Data? {
        guard let d = manufacturerData, d.count >= 2 else { return nil }
        return Data(d.dropFirst(2))
    }
}
