// PacketTunnelProvider.swift  (Network Extension target only)
import NetworkExtension
import Foundation

class PacketTunnelProvider: NEPacketTunnelProvider {
    private var counter: UInt = 1
    private let sharedFileURL: URL = {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.com.yourcompany.mDNSShark")!
            .appendingPathComponent("packets.log")
    }()

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.ipv4Settings = NEIPv4Settings(addresses: ["192.168.100.1"],
                                               subnetMasks: ["255.255.255.0"])
        settings.mtu = 1500
        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error { completionHandler(error); return }
            self?.readLoop()
            completionHandler(nil)
        }
    }

    private func readLoop() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else { return }
            for (i, data) in packets.enumerated() {
                self.write(self.parse(data, family: protocols[i]))
            }
            self.readLoop()
        }
    }

    private func parse(_ data: Data, family: NSNumber) -> PacketModel {
        let hex = data.map { String(format: "%02x", $0) }.joined(separator: " ")
        let bytes = [UInt8](data)

        guard data.count >= 20, family.int32Value == 2 /* AF_INET */ else {
            return make(src: "0.0.0.0", dst: "0.0.0.0", proto: "Other",
                        len: data.count, info: "Non-IPv4", hex: hex)
        }

        let ihl     = Int(bytes[0] & 0x0F) * 4
        let ipProto = bytes[9]
        let src     = "\(bytes[12]).\(bytes[13]).\(bytes[14]).\(bytes[15])"
        let dst     = "\(bytes[16]).\(bytes[17]).\(bytes[18]).\(bytes[19])"
        let payload = Array(bytes.dropFirst(ihl))

        var proto = "Other"; var sPort: Int? = nil; var dPort: Int? = nil; var info = ""

        switch ipProto {
        case 6:  // TCP
            if payload.count >= 14 {
                sPort = Int(payload[0]) << 8 | Int(payload[1])
                dPort = Int(payload[2]) << 8 | Int(payload[3])
                info  = decodeTCPFlags(payload[13])
                proto = dPort == 443 || sPort == 443 ? "HTTPS"
                      : dPort == 80  || sPort == 80  ? "HTTP" : "TCP"
            } else { proto = "TCP" }

        case 17: // UDP
            if payload.count >= 4 {
                sPort = Int(payload[0]) << 8 | Int(payload[1])
                dPort = Int(payload[2]) << 8 | Int(payload[3])
                if dPort == 53 || sPort == 53 {
                    proto = "DNS"
                    info  = parseDNS(Array(payload.dropFirst(8)))
                } else if dPort == 5353 || sPort == 5353 {
                    proto = "mDNS"; info = "Multicast DNS"
                } else { proto = "UDP"; info = "UDP \(sPort ?? 0) → \(dPort ?? 0)" }
            } else { proto = "UDP" }

        case 1:  // ICMP
            proto = "ICMP"
            if !payload.isEmpty { info = decodeICMP(payload[0]) }

        default:
            proto = "IP(\(ipProto))"
        }

        let m = PacketModel(frameNumber: Int(counter), timestamp: Date(),
                            sourceIP: src, destinationIP: dst,
                            sourcePort: sPort, destinationPort: dPort,
                            protocolName: proto, length: data.count,
                            info: info.isEmpty ? "\(proto) packet" : info,
                            hexDump: hex)
        counter += 1
        return m
    }

    private func make(src: String, dst: String, proto: String,
                      len: Int, info: String, hex: String) -> PacketModel {
        let m = PacketModel(frameNumber: Int(counter), timestamp: Date(),
                            sourceIP: src, destinationIP: dst,
                            protocolName: proto, length: len, info: info, hexDump: hex)
        counter += 1
        return m
    }

    private func decodeTCPFlags(_ f: UInt8) -> String {
        var p: [String] = []
        if f & 0x01 != 0 { p.append("FIN") }
        if f & 0x02 != 0 { p.append("SYN") }
        if f & 0x04 != 0 { p.append("RST") }
        if f & 0x08 != 0 { p.append("PSH") }
        if f & 0x10 != 0 { p.append("ACK") }
        if f & 0x20 != 0 { p.append("URG") }
        return p.isEmpty ? "TCP" : "[" + p.joined(separator: ", ") + "]"
    }

    private func decodeICMP(_ type: UInt8) -> String {
        switch type {
        case 0:  return "Echo Reply"
        case 8:  return "Echo Request (ping)"
        case 3:  return "Destination Unreachable"
        case 11: return "Time Exceeded"
        default: return "ICMP Type \(type)"
        }
    }

    private func parseDNS(_ bytes: [UInt8]) -> String {
        var labels: [String] = []; var i = 4
        while i < bytes.count {
            let len = Int(bytes[i]); i += 1
            if len == 0 { break }
            guard i + len <= bytes.count else { break }
            if let s = String(bytes: Array(bytes[i..<i+len]), encoding: .utf8) { labels.append(s) }
            i += len
        }
        return labels.isEmpty ? "DNS query" : "Query: \(labels.joined(separator: "."))"
    }

    private func write(_ packet: PacketModel) {
        guard let json = try? { () -> String in
            let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601
            return String(data: try enc.encode(packet), encoding: .utf8)!
        }() else { return }
        let line = json + "\n"
        if FileManager.default.fileExists(atPath: sharedFileURL.path),
           let fh = try? FileHandle(forWritingTo: sharedFileURL) {
            fh.seekToEndOfFile()
            fh.write(line.data(using: .utf8)!)
            fh.closeFile()
        } else {
            try? line.write(to: sharedFileURL, atomically: true, encoding: .utf8)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        completionHandler()
    }
}
