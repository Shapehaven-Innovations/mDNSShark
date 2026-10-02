// PacketTunnelProvider.swift (compiled into PacketTunnel target)
import NetworkExtension
import Foundation
import Darwin
import os

class PacketTunnelProvider: NEPacketTunnelProvider {
    private var counter: UInt = 1          // mutated only on logQueue
    private var forwarder: PacketForwarder?
    private lazy var pcapWriter = PCAPWriter(fileURL: pcapFileURL)
    private let logQueue = DispatchQueue(label: "com.mDNSShark.provider.log")
    private var logHandle: FileHandle?
    private var running = false            // written by stopTunnel; read on NE queue in readLoop callback
    private let logger = Logger(subsystem: "com.mDNSShark.PacketTunnel", category: "routing")

    // Recorded once at startTunnel so stopTunnel can put a real answer in
    // capture-meta.json instead of an empty string: without this, a pcap
    // showing zero LAN traffic is unfalsifiable, so there's no way to tell
    // "the LAN route was never added" (en0 not found, wrong family, etc.)
    // apart from "the route was added but the on-link route still won".
    private var detectedWiFiIP = ""
    private var lanRouteStatus = "not attempted (includeAllNetworksInCapture off)"

    private let sharedFileURL: URL = {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.beta.mDNSShark")!
            .appendingPathComponent("packets.log")
    }()

    private let pcapFileURL: URL = {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.beta.mDNSShark")!
            .appendingPathComponent("capture.pcap")
    }()

    private let metaFileURL: URL = {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.beta.mDNSShark")!
            .appendingPathComponent("capture-meta.json")
    }()

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        // 100.64.0.0/10 (RFC 6598 CGNAT range) keeps the tunnel subnet from colliding with any real LAN, unlike the old 192.168.100.1/24 that matched a tester's Wi-Fi.
        let ipv4 = NEIPv4Settings(addresses: ["100.64.0.1"], subnetMasks: ["255.255.255.0"])
        var includedRoutes = [NEIPv4Route.default()]
        // Opt-in LAN capture adds a Wi-Fi subnet route (recorded in lanRouteStatus), though iOS keeps router traffic on Wi-Fi so it is never captured.
        if SharedSettings.includeAllNetworksInCapture {
            if let wifi = currentWiFiIPv4Network() {
                detectedWiFiIP = wifi.address
                lanRouteStatus = "added \(wifi.networkAddress)/\(wifi.subnetMask)"
                includedRoutes.append(NEIPv4Route(destinationAddress: wifi.networkAddress, subnetMask: wifi.subnetMask))
            } else {
                lanRouteStatus = "not added (could not determine en0's IPv4 address/netmask)"
            }
            logger.debug("startTunnel: includeAllNetworksInCapture=true, en0=\(self.detectedWiFiIP, privacy: .private), lanRoute=\(self.lanRouteStatus, privacy: .public)")
        }
        ipv4.includedRoutes = includedRoutes
        settings.ipv4Settings = ipv4
        settings.dnsSettings = NEDNSSettings(servers: SharedSettings.dnsServers)
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
                // PCAP unavailable (disk full, permissions) - tunnel still runs, export will fail
            }

            let fwd = PacketForwarder(
                flow: self.packetFlow,
                onDecryptedHTTPS: { [weak self] payload, domain in
                    self?.handleDecryptedHTTPS(payload: payload, domain: domain)
                },
                onPacket: { [weak self] rawIP, direction, isReconstructed in
                    self?.handle(rawIP: rawIP, direction: direction, isReconstructed: isReconstructed)
                }
            )
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
            guard SharedSettings.captureFilterProtocols.contains(packet.protocolName) else { return }
            self.writeJSON(packet)
            self.pcapWriter.appendPacket(rawIP, at: packet.timestamp, isReconstructed: isReconstructed)
        }
    }

    private func handleDecryptedHTTPS(payload: Data, domain: String) {
        logQueue.async { [weak self] in
            guard let self else { return }
            let text = String(data: payload, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard let text, !text.isEmpty else { return }
            let packet = PacketModel(
                frameNumber: Int(self.counter),
                timestamp: Date(),
                sourceIP: "device",
                destinationIP: domain,
                sourcePort: nil,
                destinationPort: 443,
                protocolName: "HTTPS",
                length: payload.count,
                info: PacketModel.tlsDecryptedInfo,
                hexDump: payload.map { String(format: "%02x", $0) }.joined(separator: " "),
                payloadText: text,
                direction: .outbound,
                isReconstructed: true
            )
            self.writeJSON(packet)
            self.counter += 1
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
            deviceWiFiIP: detectedWiFiIP,
            tunnelIP: "100.64.0.1",
            totalPackets: totalPackets,
            lanRouteStatus: lanRouteStatus
        )
        if let data = try? JSONSerialization.data(withJSONObject: meta, options: .prettyPrinted) {
            try? data.write(to: metaFileURL)
        }
        completionHandler()
    }

    // MARK: - LAN route detection

    /// The device's current Wi-Fi (`en0`) IPv4 address + netmask, reduced to
    /// the network address the interface is actually on-link for (e.g.
    /// `192.168.100.42`/`255.255.255.0` → `192.168.100.0`/`255.255.255.0`).
    /// Used to add an explicit, more-specific `NEIPv4Route` for that subnet
    /// alongside the tunnel's default route, so opt-in LAN capture sees that subnet.
    /// Same `getifaddrs`/`en0` technique `LocalDeviceScanner.getWiFiAddress()`
    /// uses in the main app target; duplicated rather than shared because
    /// that type lives in the app target, not this extension's.
    private func currentWiFiIPv4Network() -> (address: String, networkAddress: String, subnetMask: String)? {
        var result: (String, String, String)?
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return nil }
        defer { freeifaddrs(ifaddr) }

        var ptr: UnsafeMutablePointer<ifaddrs>? = first
        while let current = ptr {
            let interface = current.pointee
            let flags = Int32(interface.ifa_flags)
            if (flags & (IFF_UP | IFF_RUNNING | IFF_LOOPBACK)) == (IFF_UP | IFF_RUNNING),
               interface.ifa_addr?.pointee.sa_family == UInt8(AF_INET),
               String(cString: interface.ifa_name) == "en0",
               let addrPtr = interface.ifa_addr, let maskPtr = interface.ifa_netmask {

                var addrHost = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                var maskHost = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                let addrRC = getnameinfo(addrPtr, socklen_t(addrPtr.pointee.sa_len), &addrHost,
                                          socklen_t(addrHost.count), nil, 0, NI_NUMERICHOST)
                let maskRC = getnameinfo(maskPtr, socklen_t(maskPtr.pointee.sa_len), &maskHost,
                                          socklen_t(maskHost.count), nil, 0, NI_NUMERICHOST)
                // A non-nil ifa_netmask can still carry a malformed/wrong-family
                // sockaddr (observed on a lo0 alias: sa_family=0), which
                // getnameinfo rejects with a nonzero return code and an
                // untouched (still-zeroed) buffer. Checking the return code
                // explicitly fails closed here instead of relying on
                // String(cString:) on a zeroed buffer happening to produce ""
                // and networkAddress happening to reject that.
                if addrRC == 0, maskRC == 0,
                   let network = Self.networkAddress(address: String(cString: addrHost),
                                                      mask: String(cString: maskHost)) {
                    result = (String(cString: addrHost), network, String(cString: maskHost))
                }
                break
            }
            ptr = interface.ifa_next
        }
        return result
    }

    private static func networkAddress(address: String, mask: String) -> String? {
        let a = address.split(separator: ".").compactMap { UInt8($0) }
        let m = mask.split(separator: ".").compactMap { UInt8($0) }
        guard a.count == 4, m.count == 4 else { return nil }
        return (0..<4).map { String(a[$0] & m[$0]) }.joined(separator: ".")
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

    // Called on logQueue - uses the persistent logHandle for atomic append.
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
