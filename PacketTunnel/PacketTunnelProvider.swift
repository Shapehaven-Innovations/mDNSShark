// PacketTunnelProvider.swift (compiled into PacketTunnel target)
import NetworkExtension
import Foundation
import Darwin
import os

class PacketTunnelProvider: NEPacketTunnelProvider {
    private var sequence = CaptureSequence()   // mutated only on logQueue
    private var forwarder: PacketForwarder?
    private var mdnsListener: BSDMDNSListener?
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

            var pcapReady = true
            do {
                try self.pcapWriter.startCapture()
            } catch {
                // PCAP unavailable (disk full, permissions) - tunnel still runs, export will fail
                pcapReady = false
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
            self.startMDNSListener(pcapReady: pcapReady)
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

    // Dispatched to logQueue so sequence, logHandle, and pcapWriter are accessed serially.
    private func handle(rawIP: Data, direction: PacketDirection, isReconstructed: Bool,
                        timestamp: Date = Date(), captureSource: PacketModel.CaptureSource = .tunnel) {
        logQueue.async { [weak self] in
            guard let self else { return }
            let packet = PacketParser.parse(rawIP, frameNumber: self.sequence.nextFrameNumber, timestamp: timestamp,
                                            direction: direction, isReconstructed: isReconstructed, captureSource: captureSource)
            guard SharedSettings.captureFilterProtocols.contains(packet.protocolName) else { return }
            // Only packets written to the pcap consume a frame number, so app frame N is Wireshark frame N.
            self.sequence.recordFrame()
            self.writeJSON(packet)
            self.pcapWriter.appendPacket(rawIP, at: packet.timestamp, isReconstructed: isReconstructed)
        }
    }

    // Decrypted requests are never written to the pcap, so they get their own D-n sequence and leave the frame counter alone.
    private func handleDecryptedHTTPS(payload: Data, domain: String) {
        logQueue.async { [weak self] in
            guard let self else { return }
            let text = String(data: payload, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard let text, !text.isEmpty else { return }
            let entry = self.sequence.recordDecryptedRequest()
            let packet = PacketModel(
                frameNumber: entry.afterFrame,
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
                isReconstructed: false,
                decryptedSequence: entry.sequence
            )
            self.writeJSON(packet)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        running = false
        forwarder?.stop()
        // The listener stops first so no datagram can reach handle() after the drain below.
        let listenerStatuses = (mdnsListener?.status, mdnsListener?.ipv6Status)
        mdnsListener?.stop()

        // Drain in-flight log writes so every appendPacket is queued before the pcap is closed and counted.
        var decryptedRequests = 0
        logQueue.sync {
            logHandle?.closeFile()
            logHandle = nil
            decryptedRequests = self.sequence.decryptedRequests
        }

        var meta = pcapWriter.stopCapture(
            deviceWiFiIP: detectedWiFiIP,
            tunnelIP: "100.64.0.1",
            decryptedRequests: decryptedRequests,
            lanRouteStatus: lanRouteStatus
        )
        meta["mdnsListener"] = mdnsListenerMeta(statuses: listenerStatuses)
        if let disclaimer = meta["disclaimer"] as? String {
            meta["disclaimer"] = disclaimer + " mDNS frames have IP and UDP headers rebuilt from socket metadata; payloads are verbatim."
        }
        if let data = try? JSONSerialization.data(withJSONObject: meta, options: .prettyPrinted) {
            try? data.write(to: metaFileURL)
        }
        completionHandler()
    }

    // MARK: - mDNS listener (docs/mdns-listener-scope.md section 2.3)

    /// Starts the multicast listener when the mDNS filter is on and the pcap opened; each datagram becomes a reconstructed frame through handle().
    private func startMDNSListener(pcapReady: Bool) {
        guard SharedSettings.captureFilterProtocols.contains("mDNS") else {
            SharedSettings.mdnsListenerStatus = "disabled (mDNS filter off)"
            return
        }
        guard pcapReady else {
            SharedSettings.mdnsListenerStatus = "not started (pcap unavailable)"
            return
        }
        let listener = BSDMDNSListener()
        listener.start { [weak self, weak listener] datagram, _ in
            guard let self, let listener, let frame = MDNSFrameBuilder.frame(datagram) else { return }
            let direction: PacketDirection = listener.ownAddresses.contains(datagram.source) ? .outbound : .inbound
            self.handle(rawIP: frame, direction: direction, isReconstructed: true,
                        timestamp: datagram.timestamp, captureSource: .mdnsListener)
        }
        mdnsListener = listener
        SharedSettings.mdnsListenerStatus = listener.status.description
        logger.info("mDNS listener: \(listener.status.description, privacy: .public)")
    }

    /// Reports the statuses sampled before stop() so the meta shows how the listener ran, not "stopped".
    private func mdnsListenerMeta(statuses: (MDNSListenerStatus?, MDNSListenerStatus?)) -> [String: Any] {
        guard let listener = mdnsListener else {
            return ["status": SharedSettings.mdnsListenerStatus, "ipv6Status": SharedSettings.mdnsListenerStatus, "frames": 0]
        }
        return MDNSListenerMeta.dictionary(status: statuses.0 ?? listener.status, ipv6Status: statuses.1 ?? listener.ipv6Status,
                                           interfaceName: listener.interfaceName, interfaceIndex: listener.interfaceIndex,
                                           stats: listener.stats)
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

    // Fractional seconds keep sub-second packet timing (plain .iso8601 drops it); shared to avoid per-packet allocation.
    private static let packetDateFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    // Called on logQueue - uses the persistent logHandle for atomic append.
    private func writeJSON(_ packet: PacketModel) {
        guard let fh = logHandle else { return }
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .custom { date, encoder in
            var c = encoder.singleValueContainer()
            try c.encode(Self.packetDateFormatter.string(from: date))
        }
        guard let jsonData = try? enc.encode(packet),
              let newline = "\n".data(using: .utf8) else { return }
        fh.write(jsonData + newline)
    }
}
