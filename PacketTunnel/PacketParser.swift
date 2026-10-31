// PacketTunnel/PacketParser.swift
// Shared into the mDNSShark target (pbxproj exception set) so PacketParserTests can reach it.
import Foundation

/// Pure summary of one raw IPv4 or IPv6 packet into a PacketModel; the caller supplies the frame number.
enum PacketParser {
    static func parse(_ data: Data, frameNumber: Int, timestamp: Date = Date(),
                      direction: PacketDirection, isReconstructed: Bool,
                      captureSource: PacketModel.CaptureSource = .tunnel) -> PacketModel {
        let hex   = data.map { String(format: "%02x", $0) }.joined(separator: " ")
        let bytes = [UInt8](data)

        let header: (src: String, dst: String, ipProto: UInt8, payload: [UInt8])?
        if data.count >= 20, bytes[0] >> 4 == 4 {
            let ihl = Int(bytes[0] & 0x0F) * 4
            header = ("\(bytes[12]).\(bytes[13]).\(bytes[14]).\(bytes[15])",
                      "\(bytes[16]).\(bytes[17]).\(bytes[18]).\(bytes[19])",
                      bytes[9], Array(bytes.dropFirst(ihl)))
        } else if data.count >= 40, bytes[0] >> 4 == 6 {
            header = (ipv6String(bytes[8..<24]), ipv6String(bytes[24..<40]), bytes[6], Array(bytes.dropFirst(40)))
        } else {
            header = nil
        }

        guard let (src, dst, ipProto, payload) = header else {
            return PacketModel(frameNumber: frameNumber, timestamp: timestamp,
                               sourceIP: "0.0.0.0", destinationIP: "0.0.0.0",
                               protocolName: "Other", length: data.count, info: "Non-IP", hexDump: hex,
                               direction: direction, isReconstructed: isReconstructed, captureSource: captureSource)
        }

        var proto = "Other"; var sPort: Int?; var dPort: Int?; var info = ""
        var payloadText: String? = nil

        switch ipProto {
        case 6:
            if payload.count >= 14 {
                sPort = Int(payload[0]) << 8 | Int(payload[1])
                dPort = Int(payload[2]) << 8 | Int(payload[3])
                info  = decodeTCPFlags(payload[13])
                proto = dPort == 443 || sPort == 443 ? "HTTPS"
                      : dPort == 80  || sPort == 80  ? "HTTP" : "TCP"
                if proto == "HTTP" {
                    let tcpHeaderLen = Int((payload[12] >> 4)) * 4
                    if payload.count > tcpHeaderLen {
                        let httpBytes = Array(payload.dropFirst(tcpHeaderLen))
                        let text = String(bytes: httpBytes, encoding: .utf8)
                        if let t = text, !t.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                            payloadText = t
                        }
                    }
                }
            } else { proto = "TCP" }
        case 17:
            if payload.count >= 4 {
                sPort = Int(payload[0]) << 8 | Int(payload[1])
                dPort = Int(payload[2]) << 8 | Int(payload[3])
                if dPort == 53 || sPort == 53 {
                    proto = "DNS"; info = parseDNS(Array(payload.dropFirst(8)))
                } else if dPort == 5353 || sPort == 5353 {
                    proto = "mDNS"; info = "Multicast DNS"
                } else {
                    proto = "UDP"; info = "UDP \(sPort ?? 0) → \(dPort ?? 0)"
                }
            } else { proto = "UDP" }
        case 1:
            proto = "ICMP"
            if !payload.isEmpty { info = decodeICMP(payload[0]) }
        case 58:
            proto = "ICMP"
            if !payload.isEmpty { info = "ICMPv6 Type \(payload[0])" }
        default:
            proto = "IP(\(ipProto))"
        }

        if isReconstructed && !info.contains("[reconstructed]") {
            info = info.isEmpty ? "[reconstructed]" : "\(info) [reconstructed]"
        }

        return PacketModel(
            frameNumber: frameNumber, timestamp: timestamp,
            sourceIP: src, destinationIP: dst,
            sourcePort: sPort, destinationPort: dPort,
            protocolName: proto, length: data.count,
            info: info.isEmpty ? "\(proto) packet" : info,
            hexDump: hex, payloadText: payloadText,
            direction: direction, isReconstructed: isReconstructed, captureSource: captureSource
        )
    }

    // MARK: - Private

    private static func ipv6String(_ slice: ArraySlice<UInt8>) -> String {
        var addr = in6_addr()
        withUnsafeMutableBytes(of: &addr) { $0.copyBytes(from: slice) }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        inet_ntop(AF_INET6, &addr, &buf, socklen_t(buf.count))
        return String(cString: buf)
    }

    private static func decodeTCPFlags(_ f: UInt8) -> String {
        var p: [String] = []
        if f & 0x01 != 0 { p.append("FIN") }
        if f & 0x02 != 0 { p.append("SYN") }
        if f & 0x04 != 0 { p.append("RST") }
        if f & 0x08 != 0 { p.append("PSH") }
        if f & 0x10 != 0 { p.append("ACK") }
        if f & 0x20 != 0 { p.append("URG") }
        return p.isEmpty ? "TCP" : "[" + p.joined(separator: ", ") + "]"
    }

    private static func decodeICMP(_ type: UInt8) -> String {
        switch type {
        case 0:  return "Echo Reply"
        case 8:  return "Echo Request (ping)"
        case 3:  return "Destination Unreachable"
        case 11: return "Time Exceeded"
        default: return "ICMP Type \(type)"
        }
    }

    // Question name starts after the 12-byte DNS header; the QR bit marks responses.
    private static func parseDNS(_ bytes: [UInt8]) -> String {
        guard bytes.count >= 12 else { return "DNS packet" }
        let isResponse = bytes[2] & 0x80 != 0
        var labels: [String] = []; var i = 12
        while i < bytes.count {
            let len = Int(bytes[i]); i += 1
            if len == 0 { break }
            guard i + len <= bytes.count else { break }
            if let s = String(bytes: Array(bytes[i..<i+len]), encoding: .utf8) { labels.append(s) }
            i += len
        }
        let kind = isResponse ? "Response" : "Query"
        return labels.isEmpty ? "DNS \(kind.lowercased())" : "\(kind): \(labels.joined(separator: "."))"
    }
}
