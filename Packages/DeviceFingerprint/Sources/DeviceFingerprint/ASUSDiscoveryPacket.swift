import Foundation

/// One decoded reply from an ASUS router/AiMesh node's `infosvr` discovery
/// responder (UDP port 9999, the "iBox"/`NET_CMD_ID_GETINFO` protocol).
/// Ground-truth data the device reported about itself — not an inference.
public struct ASUSDiscoveryReply: Sendable {
    public let mac: String?
    public let model: String?             // ASUS ProductID, e.g. "RT-AC68U"
    public let firmwareVersion: String?
    public let ssid: String?
}

/// Encoder/decoder for ASUS's `infosvr` discovery-protocol wire format
/// (the "iBox communication protocol"). Reference: ASUS's own GPL firmware
/// source, `RMerl/asuswrt-merlin` (an enhanced fork of stock Asuswrt):
///   - `release/src/router/shared/iboxcom.h` — struct/enum definitions,
///     built with `#pragma pack(1)` (no padding between fields).
///   - `release/src/router/infosvr/common.c`, `processPacket()` — shows
///     exactly how a `NET_CMD_ID_GETINFO` request is answered.
///
/// Wire layout (all multi-byte integers little-endian — confirmed against
/// the well-known 8-byte GETINFO header `0C 15 1F 00 00 00 00 00`, which
/// decodes cleanly as ServiceID=0x0C, PacketType=0x15 (CMD), OpCode=0x001F
/// little-endian (`NET_CMD_ID_GETINFO` = 31), Info=0). That header is only
/// the first 8 bytes of the actual request, though: `infosvr.c`'s
/// `processReq()` does `iRcv = RECV(sockfd, pdubuf, INFO_PDU_LENGTH, ...);
/// if (iRcv != INFO_PDU_LENGTH) { closesocket(sockfd); return -1; }` where
/// `INFO_PDU_LENGTH` = 512 (`iboxcom.h`) — present from 2014 through current
/// `asuswrt-merlin.ng` master. A short datagram is silently discarded (and
/// `closesocket()` on that path can stall the listener for up to a second),
/// so `probe()` sends the full 512-byte datagram: the 8-byte header
/// followed by 504 zero bytes.
///
///   offset 0    IBOX_COMM_PKT_RES header (8 bytes):
///                 ServiceID(1) = 0x0C (NET_SERVICE_ID_IBOX_INFO)
///                 PacketType(1) = 0x16 (NET_PACKET_TYPE_RES) on a reply
///                 OpCode(2, LE) = 0x001F (echoes NET_CMD_ID_GETINFO)
///                 Info(4, LE)   = transaction id (unused here)
///   offset 8    PrinterInfo[128]   (unused by us)
///   offset 136  SSID[32]
///   offset 168  NetMask[32]        (unused by us)
///   offset 200  ProductID[32]      -> model
///   offset 232  FirmwareVersion[16]
///   offset 248  OperationMode[1]   (unused by us)
///   offset 249  MacAddress[6]      (raw bytes, not a string)
///   offset 255  sw_mode[1]         (unused by us)
///
/// Every string field is a fixed-width buffer holding a NUL-terminated C
/// string (`strcpy`'d in the original firmware). Note this does NOT mean
/// the bytes after the NUL are reliably zero: `common.c`'s response buffer
/// (`pdubuf_res`) is a persistent global that `processPacket()` only
/// `memset`s to `sizeof(ginfo)` bytes (a pointer-sized bug in the original
/// C, not `sizeof(*ginfo)`), so bytes past a field's NUL can be leftover
/// garbage from a previous reply rather than zero padding. The decoder
/// below only ever reads up to the first NUL, so it's unaffected either way
/// — this note exists purely so nobody "fixes" the decoder to expect
/// zero-padding that the real firmware doesn't guarantee.
public enum ASUSDiscoveryPacket {
    private static let serviceIDIboxInfo: UInt8 = 0x0C   // NET_SERVICE_ID_IBOX_INFO
    private static let packetTypeCmd: UInt8 = 0x15        // NET_PACKET_TYPE_CMD
    private static let packetTypeRes: UInt8 = 0x16        // NET_PACKET_TYPE_RES
    private static let opCodeGetInfo: UInt16 = 0x001F     // NET_CMD_ID_GETINFO

    private static let headerLength = 8
    private static let printerInfoLength = 128
    private static let ssidLength = 32
    private static let netmaskLength = 32
    private static let productIDLength = 32
    private static let firmwareVersionLength = 16
    private static let operationModeLength = 1
    private static let macLength = 6

    private static let ssidOffset = headerLength + printerInfoLength                 // 136
    private static let netmaskOffset = ssidOffset + ssidLength                       // 168
    private static let productIDOffset = netmaskOffset + netmaskLength               // 200
    private static let firmwareVersionOffset = productIDOffset + productIDLength     // 232
    private static let operationModeOffset = firmwareVersionOffset + firmwareVersionLength // 248
    private static let macOffset = operationModeOffset + operationModeLength         // 249
    /// Minimum byte count needed to safely read every field we care about
    /// (through the end of the 6-byte MAC address at offset 249..254).
    private static let minimumReplyLength = macOffset + macLength                    // 255

    /// Size of the whole UDP datagram `infosvr` requires (`INFO_PDU_LENGTH`
    /// in `iboxcom.h`). `processReq()` in `infosvr.c` rejects (and silently
    /// discards) anything shorter — see the type-level doc comment above.
    private static let requestDatagramLength = 512

    /// The `NET_CMD_ID_GETINFO` probe request: the 8-byte header followed
    /// by zero padding out to the full 512-byte `INFO_PDU_LENGTH` datagram
    /// `infosvr` requires before it will even look at the packet.
    public static func probe() -> Data {
        var bytes = [UInt8](repeating: 0, count: requestDatagramLength)
        bytes[0] = serviceIDIboxInfo
        bytes[1] = packetTypeCmd
        bytes[2] = UInt8(opCodeGetInfo & 0xFF)
        bytes[3] = UInt8(opCodeGetInfo >> 8)
        // bytes[4...7] = Info (transaction id) — left as 0, unused.
        // bytes[8...511] = zero padding, required to reach INFO_PDU_LENGTH.
        return Data(bytes)
    }

    public static func decode(_ data: Data) -> ASUSDiscoveryReply? {
        guard data.count >= minimumReplyLength else { return nil }
        let bytes = Array(data)

        guard bytes[0] == serviceIDIboxInfo,
              bytes[1] == packetTypeRes,
              bytes[2] == UInt8(opCodeGetInfo & 0xFF),
              bytes[3] == UInt8(opCodeGetInfo >> 8) else { return nil }

        let ssid = cString(bytes, offset: ssidOffset, length: ssidLength)
        let model = cString(bytes, offset: productIDOffset, length: productIDLength)
        let firmwareVersion = cString(bytes, offset: firmwareVersionOffset, length: firmwareVersionLength)

        let macBytes = bytes[macOffset..<(macOffset + macLength)]
        let mac = macBytes.contains(where: { $0 != 0 })
            ? macBytes.map { String(format: "%02x", $0) }.joined(separator: ":")
            : nil

        guard mac != nil || model != nil || ssid != nil || firmwareVersion != nil else { return nil }
        return ASUSDiscoveryReply(mac: mac, model: model, firmwareVersion: firmwareVersion, ssid: ssid)
    }

    /// Reads a NUL-terminated string out of a fixed-width field — bytes
    /// after the NUL are ignored and not assumed to be zero (see the
    /// type-level doc comment). Returns nil for an empty (NUL-at-offset-0)
    /// field or invalid UTF-8, rather than an empty string — same
    /// discipline as `UbiquitiDiscoveryPacket`.
    private static func cString(_ bytes: [UInt8], offset: Int, length: Int) -> String? {
        guard offset + length <= bytes.count else { return nil }
        let slice = bytes[offset..<(offset + length)]
        let nulIndex = slice.firstIndex(of: 0) ?? slice.endIndex
        guard nulIndex > slice.startIndex else { return nil }
        return String(bytes: slice[slice.startIndex..<nulIndex], encoding: .utf8)
    }
}
