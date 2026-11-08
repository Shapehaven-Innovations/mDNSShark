import Foundation
import DeviceFingerprint

/// One advertisement as the in-memory log keeps it. Never written to disk except by a user-started export.
struct BLEAdvertisementRecord: Identifiable, Equatable, Codable {
    let id: UUID
    let at: Date
    /// Session row id, not the CoreBluetooth identifier.
    let peripheralID: UUID
    let name: String?
    let companyID: UInt16?
    let companyName: String?
    let serviceUUIDs: [String]
    let rssi: Int
    let txPower: Int?
    let isConnectable: Bool?
    let manufacturerDataHex: String?
    let serviceDataHex: [String: String]

    init(sighting: BLESighting, parsed: BLEParsedAdvertisement, peripheralID: UUID) {
        id = UUID()
        at = sighting.at
        self.peripheralID = peripheralID
        name = parsed.displayName
        companyID = parsed.companyID
        companyName = parsed.companyName
        serviceUUIDs = parsed.serviceUUIDs
        rssi = sighting.rssi
        txPower = sighting.fields.txPower
        isConnectable = sighting.fields.isConnectable
        manufacturerDataHex = sighting.fields.manufacturerData.map(HexFormatting.hex)
        var data: [String: String] = [:]
        for (key, value) in sighting.fields.serviceData { data[BLEServiceNameTable.shortForm(key)] = HexFormatting.hex(value) }
        serviceDataHex = data
    }
}

enum HexFormatting {
    /// Uppercase bytes separated by single spaces, for example "4C 00 10 05".
    static func hex(_ data: Data) -> String {
        guard !data.isEmpty else { return "" }
        var out: [UInt8] = []
        out.reserveCapacity(data.count * 3 - 1)
        for (i, byte) in data.enumerated() {
            if i > 0 { out.append(0x20) }
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0F)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    private static let digits = Array("0123456789ABCDEF".utf8)
}
