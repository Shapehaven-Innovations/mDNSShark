// PacketTunnelProvider.swift (compiled into PacketTunnel target)
import NetworkExtension
import Foundation

class PacketTunnelProvider: NEPacketTunnelProvider {
    private var counter: UInt = 1          // mutated only on logQueue
    private var forwarder: PacketForwarder?
    private lazy var pcapWriter = PCAPWriter(fileURL: pcapFileURL)
    private let logQueue = DispatchQueue(label: "com.mDNSShark.provider.log")
    private var logHandle: FileHandle?
    private var running = false            // written by stopTunnel; read on NE queue in readLoop callback

    private let sharedFileURL: URL = {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.org.shapehaveninnovations.mDNSShark")!
            .appendingPathComponent("packets.log")
    }()

    private let pcapFileURL: URL = {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.org.shapehaveninnovations.mDNSShark")!
            .appendingPathComponent("capture.pcap")
    }()

    private let metaFileURL: URL = {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.org.shapehaveninnovations.mDNSShark")!
            .appendingPathComponent("capture-meta.json")
    }()

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["192.168.100.1"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        settings.dnsSettings = NEDNSSettings(servers: ["8.8.8.8", "8.8.4.4"])
        settings.mtu = 1500

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error { completionHandler(error); return }

            // Clear previous session log and open a persistent write handle
            try? "".write(to: self.sharedFileURL, atomically: true, encoding: .utf8)
            self.logHandle = try? FileHandle(forWritingTo: self.sharedFileURL)

            do {
                try self.pcapWriter.startCapture()
            } catch {
                // PCAP unavailable (disk full, permissions) — tunnel still runs, export will fail
            }

            let fwd = PacketForwarder(flow: self.packetFlow) { [weak self] rawIP, direction, isReconstructed in
                self?.handle(rawIP: rawIP, direction: direction, isReconstructed: isReconstructed)
            }
            fwd.start()
            self.forwarder = fwd
            self.running = true
            self.readLoop()
            completionHandler(nil)
        }
    }

    private func readLoop() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, self.running else { return }
            self.forwarder?.handleOutbound(packets, protocols: protocols)
            self.readLoop()
        }
    }

    // Dispatched to logQueue so counter, logHandle, and pcapWriter are accessed serially.
    private func handle(rawIP: Data, direction: PacketDirection, isReconstructed: Bool) {
        logQueue.async { [weak self] in
            guard let self else { return }
            let packet = self.parse(rawIP, direction: direction, isReconstructed: isReconstructed)
            self.writeJSON(packet)
            self.pcapWriter.appendPacket(rawIP, at: packet.timestamp, isReconstructed: isReconstructed)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        running = false
        forwarder?.stop()

        // Drain in-flight log writes; capture counter after all packets are processed.
        var totalPackets = 0
        logQueue.sync {
            logHandle?.closeFile()
            logHandle = nil
            totalPackets = Int(self.counter) - 1
        }

        let meta = pcapWriter.stopCapture(
            deviceWiFiIP: "",
            tunnelIP: "192.168.100.1",
            totalPackets: totalPackets
        )
        if let data = try? JSONSerialization.data(withJSONObject: meta, options: .prettyPrinted) {
            try? data.write(to: metaFileURL)
        }
        completionHandler()
    }

    // MARK: - Parsing (called only on logQueue)

    private func parse(_ data: Data, direction: PacketDirection, isReconstructed: Bool) -> PacketModel {
        let hex   = data.map { String(format: "%02x", $0) }.joined(separator: " ")
        let bytes = [UInt8](data)

        guard data.count >= 20, bytes[0] >> 4 == 4 else {
            return make(src: "0.0.0.0", dst: "0.0.0.0", proto: "Other",
                        len: data.count, info: "Non-IPv4", hex: hex,
                        direction: direction, isReconstructed: isReconstructed)
        }

        let ihl     = Int(bytes[0] & 0x0F) * 4
        let ipProto = bytes[9]
        let src     = "\(bytes[12]).\(bytes[13]).\(bytes[14]).\(bytes[15])"
        let dst     = "\(bytes[16]).\(bytes[17]).\(bytes[18]).\(bytes[19])"
        let payload = Array(bytes.dropFirst(ihl))

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
        default:
            proto = "IP(\(ipProto))"
        }

        if isReconstructed && !info.contains("[reconstructed]") {
            info = info.isEmpty ? "[reconstructed]" : "\(info) [reconstructed]"
        }

        let m = PacketModel(
            frameNumber: Int(counter), timestamp: Date(),
            sourceIP: src, destinationIP: dst,
            sourcePort: sPort, destinationPort: dPort,
            protocolName: proto, length: data.count,
            info: info.isEmpty ? "\(proto) packet" : info,
            hexDump: hex, payloadText: payloadText,
            direction: direction, isReconstructed: isReconstructed
        )
        counter += 1
        return m
    }

    private func make(src: String, dst: String, proto: String, len: Int,
                      info: String, hex: String,
                      direction: PacketDirection, isReconstructed: Bool) -> PacketModel {
        let m = PacketModel(
            frameNumber: Int(counter), timestamp: Date(),
            sourceIP: src, destinationIP: dst,
            protocolName: proto, length: len, info: info, hexDump: hex,
            direction: direction, isReconstructed: isReconstructed
        )
        counter += 1
        return m
    }

    // Called on logQueue — uses the persistent logHandle for atomic append.
    private func writeJSON(_ packet: PacketModel) {
        guard let fh = logHandle else { return }
        let enc = JSONEncoder(); enc.dateEncodingStrategy = .iso8601
        guard let jsonData = try? enc.encode(packet),
              let newline = "\n".data(using: .utf8) else { return }
        fh.write(jsonData + newline)
    }

    // MARK: - Protocol helpers

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
}
