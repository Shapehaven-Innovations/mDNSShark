// PacketTunnel/MDNSFrameBuilder.swift
// Shared into the mDNSShark target (pbxproj exception set) so MDNSFrameBuilderTests can reach it.
import Foundation

/// One received mDNS datagram plus the socket metadata needed to rebuild its IP and UDP headers.
struct MDNSDatagram {
    let payload: Data
    /// 4 bytes (IPv4) or 16 bytes (IPv6), network order.
    let source: [UInt8]
    let destination: [UInt8]
    let sourcePort: UInt16
    let destinationPort: UInt16
    /// IP_RECVTTL or IPV6_RECVHOPLIMIT value; nil when the control message was missing.
    let ttl: UInt8?
    /// Kernel receive time (SCM_TIMESTAMP) or the recvmsg wall clock.
    let timestamp: Date
}

/// Pure header synthesis for LINKTYPE_RAW records: the payload is verbatim, every header field comes from the datagram's metadata.
enum MDNSFrameBuilder {
    /// RFC 6762 section 11: mDNS is sent with TTL 255, so that is the value when the socket did not report one.
    static let fallbackTTL: UInt8 = 255

    /// IPv4 or IPv6 frame chosen by address length; nil when the two addresses are not both 4 or both 16 bytes.
    static func frame(_ d: MDNSDatagram) -> Data? {
        switch (d.source.count, d.destination.count) {
        case (4, 4): return ipv4Frame(d)
        case (16, 16): return ipv6Frame(d)
        default: return nil
        }
    }

    /// 20-byte IPv4 header (DF set, ID 0) + 8-byte UDP header + payload, both checksums computed.
    static func ipv4Frame(_ d: MDNSDatagram) -> Data {
        let udpLen = 8 + d.payload.count
        var bytes: [UInt8] = []
        bytes.reserveCapacity(20 + udpLen)
        bytes.append(0x45)
        bytes.append(0x00)
        appendBE16(&bytes, UInt16(20 + udpLen))
        appendBE16(&bytes, 0)        // identification
        appendBE16(&bytes, 0x4000)   // flags: DF
        bytes.append(d.ttl ?? fallbackTTL)
        bytes.append(17)
        appendBE16(&bytes, 0)        // header checksum, patched below
        bytes += d.source
        bytes += d.destination
        appendUDP(&bytes, d, udpLen: udpLen)

        let ipChecksum = PacketChecksum.internetChecksum(bytes[0..<20])
        bytes[10] = UInt8(ipChecksum >> 8); bytes[11] = UInt8(ipChecksum & 0xFF)

        var pseudo = d.source + d.destination + [0, 17]
        appendBE16(&pseudo, UInt16(udpLen))
        patchUDPChecksum(&bytes, udpOffset: 20, pseudoHeader: pseudo)
        return Data(bytes)
    }

    /// 40-byte IPv6 header + 8-byte UDP header + payload; the UDP checksum is mandatory here.
    static func ipv6Frame(_ d: MDNSDatagram) -> Data {
        let udpLen = 8 + d.payload.count
        var bytes: [UInt8] = []
        bytes.reserveCapacity(40 + udpLen)
        bytes += [0x60, 0, 0, 0]     // version 6, traffic class 0, flow label 0
        appendBE16(&bytes, UInt16(udpLen))
        bytes.append(17)
        bytes.append(d.ttl ?? fallbackTTL)
        bytes += d.source
        bytes += d.destination
        appendUDP(&bytes, d, udpLen: udpLen)

        let len = UInt32(udpLen)
        let pseudo = d.source + d.destination
            + [UInt8(len >> 24), UInt8(len >> 16 & 0xFF), UInt8(len >> 8 & 0xFF), UInt8(len & 0xFF)]
            + [0, 0, 0, 17]
        patchUDPChecksum(&bytes, udpOffset: 40, pseudoHeader: pseudo)
        return Data(bytes)
    }

    // MARK: - Private

    private static func appendUDP(_ bytes: inout [UInt8], _ d: MDNSDatagram, udpLen: Int) {
        appendBE16(&bytes, d.sourcePort)
        appendBE16(&bytes, d.destinationPort)
        appendBE16(&bytes, UInt16(udpLen))
        appendBE16(&bytes, 0)        // UDP checksum, patched below
        bytes += d.payload
    }

    /// RFC 768 and RFC 2460: a computed checksum of 0x0000 is transmitted as 0xFFFF.
    private static func patchUDPChecksum(_ bytes: inout [UInt8], udpOffset: Int, pseudoHeader: [UInt8]) {
        var sum = PacketChecksum.internetChecksum(pseudoHeader + bytes[udpOffset...])
        if sum == 0 { sum = 0xFFFF }
        bytes[udpOffset + 6] = UInt8(sum >> 8); bytes[udpOffset + 7] = UInt8(sum & 0xFF)
    }

    private static func appendBE16(_ bytes: inout [UInt8], _ v: UInt16) {
        bytes.append(UInt8(v >> 8)); bytes.append(UInt8(v & 0xFF))
    }
}
