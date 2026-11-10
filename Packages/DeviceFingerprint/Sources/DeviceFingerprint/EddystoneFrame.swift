import Foundation

/// One Eddystone frame from service data for 0xFEAA, or the Google Find Hub tracker frame that shares the UUID.
public enum EddystoneFrame: Equatable, Sendable {
    case uid(namespace: String, instance: String, txPower: Int8)
    case url(String, txPower: Int8)
    case tlm(batteryMilliVolts: UInt16?, temperatureCelsius: Double?)
    case eid
    /// Frame type 0x40, or 0x41 when unwanted tracking protection is on; a 20 or 32 byte EID and an optional flags byte.
    case findHub(trackingProtection: Bool)
    case unknown(UInt8)

    public static let serviceUUID = "FEAA"

    private static let schemes = ["http://www.", "https://www.", "http://", "https://"]
    private static let expansions = [".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/",
                                     ".com", ".org", ".edu", ".net", ".info", ".biz", ".gov"]

    public static func parse(serviceData: Data) -> EddystoneFrame? {
        let b = Array(serviceData)
        guard let type = b.first else { return nil }
        switch type {
        case 0x00:
            guard b.count >= 18 else { return nil }
            return .uid(namespace: hex(b[2..<12]), instance: hex(b[12..<18]), txPower: Int8(bitPattern: b[1]))
        case 0x10:
            guard b.count >= 3, Int(b[2]) < schemes.count else { return nil }
            var url = schemes[Int(b[2])]
            for byte in b.dropFirst(3) {
                if Int(byte) < expansions.count { url += expansions[Int(byte)] }
                else if byte > 0x20, byte < 0x7F { url += String(UnicodeScalar(byte)) }
            }
            return .url(url, txPower: Int8(bitPattern: b[1]))
        case 0x20:
            guard b.count >= 2, b[1] == 0 else { return .tlm(batteryMilliVolts: nil, temperatureCelsius: nil) }
            var battery: UInt16?
            var temperature: Double?
            if b.count >= 4 {
                let v = UInt16(b[2]) << 8 | UInt16(b[3])
                if v != 0 { battery = v }
            }
            if b.count >= 6 {
                let raw = UInt16(b[4]) << 8 | UInt16(b[5])
                if raw != 0x8000 { temperature = Double(Int16(bitPattern: raw)) / 256.0 }
            }
            return .tlm(batteryMilliVolts: battery, temperatureCelsius: temperature)
        case 0x30:
            return .eid
        case 0x40, 0x41:
            guard [21, 22, 33, 34].contains(b.count) else { return nil }
            return .findHub(trackingProtection: type == 0x41)
        default:
            return .unknown(type)
        }
    }

    private static func hex(_ bytes: ArraySlice<UInt8>) -> String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }
}
