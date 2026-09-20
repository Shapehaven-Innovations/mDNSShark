import Foundation

/// One decoded reply from a Ubiquiti device's discovery-protocol responder
/// (UDP port 10001). Ground-truth data the device reported about itself —
/// not an inference.
public struct UbiquitiDiscoveryReply: Sendable {
    public let mac: String?
    public let firmware: String?
    public let hostname: String?
    public let model: String?
    public let serial: String?
}

/// Encoder/decoder for the Ubiquiti/UBNT discovery-protocol wire format:
/// a 4-byte probe (`version, type, len-hi, len-lo`), and a reply with the
/// same 4-byte header followed by `type(1) len(2-BE) value` TLVs.
/// Reference: nmap's ubiquiti-discovery.nse, Wireshark's `ubdp` dissector.
public enum UbiquitiDiscoveryPacket {
    private static let tlvHostname: UInt8 = 0x0B
    private static let tlvMac: UInt8 = 0x01
    private static let tlvMacAndIP: UInt8 = 0x02
    private static let tlvFirmware: UInt8 = 0x03
    private static let tlvSerial: UInt8 = 0x13
    private static let tlvModelV1: UInt8 = 0x14
    private static let tlvModelV2: UInt8 = 0x15

    public static func probeV1() -> Data { Data([0x01, 0x00, 0x00, 0x00]) }
    public static func probeV2() -> Data { Data([0x02, 0x08, 0x00, 0x00]) }

    public static func decode(_ data: Data) -> UbiquitiDiscoveryReply? {
        guard data.count >= 4 else { return nil }
        let bytes = Array(data)
        let body = bytes[4...]

        var mac: String?, firmware: String?, hostname: String?, model: String?, serial: String?
        var i = body.startIndex
        while i + 3 <= body.endIndex {
            let type = body[i]
            let len = Int(body[i + 1]) << 8 | Int(body[i + 2])
            let valueStart = i + 3
            let valueEnd = valueStart + len
            guard valueEnd <= body.endIndex else { break } // truncated TLV — stop, keep what we have
            let value = body[valueStart..<valueEnd]

            switch type {
            case tlvHostname: hostname = String(bytes: value, encoding: .utf8)
            case tlvMac where value.count == 6:
                mac = value.map { String(format: "%02x", $0) }.joined(separator: ":")
            case tlvMacAndIP where value.count >= 6 && mac == nil:
                mac = value.prefix(6).map { String(format: "%02x", $0) }.joined(separator: ":")
            case tlvFirmware: firmware = String(bytes: value, encoding: .utf8)
            case tlvSerial: serial = String(bytes: value, encoding: .utf8)
            case tlvModelV1, tlvModelV2: model = String(bytes: value, encoding: .utf8)
            default: break
            }
            i = valueEnd
        }

        guard mac != nil || hostname != nil || model != nil else { return nil }
        return UbiquitiDiscoveryReply(mac: mac, firmware: firmware, hostname: hostname, model: model, serial: serial)
    }
}
