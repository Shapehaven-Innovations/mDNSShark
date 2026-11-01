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
    // Start and stop bodies both run on this serial queue, so stopTunnel arriving before the settings completion cannot interleave with startup.
    private let lifecycleQueue = DispatchQueue(label: "com.mDNSShark.provider.lifecycle")
    private var stopped = false            // lifecycleQueue only
    /// What startMDNSListener wrote this session; nil when stopTunnel ran before startup reached it (lifecycleQueue only).
    private var mdnsListenerStatusThisSession: String?
    private let runningLock = OSAllocatedUnfairLock(initialState: false)   // read on the NE queue in readLoop
    private let logger = Logger(subsystem: "com.mDNSShark.PacketTunnel", category: "routing")

    /// Recorded at startTunnel so capture-meta.json can tell "the LAN route was never added" apart from "added but the on-link route still won".
    private var lanInterfaceIPv4 = ""
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
        // Opt-in LAN capture adds the LAN subnet route (recorded in lanRouteStatus), though iOS keeps router traffic on the LAN interface so it is never captured.
        // The subnet comes from the listener's interface ranking (LANRouteSelection), never from a BSD name such as en0.
        if SharedSettings.includeAllNetworksInCapture {
            if let lan = LANRouteSelection.route(from: BSDMDNSListener.interfaceDescriptors()) {
                lanInterfaceIPv4 = lan.addressText
                lanRouteStatus = "added \(lan.networkText)/\(lan.netmaskText) via \(lan.interfaceName)"
                includedRoutes.append(NEIPv4Route(destinationAddress: lan.networkText, subnetMask: lan.netmaskText))
            } else {
                lanRouteStatus = "not added (no running interface with a routable IPv4 address and netmask)"
            }
            logger.debug("startTunnel: includeAllNetworksInCapture=true, lanIPv4=\(self.lanInterfaceIPv4, privacy: .private), lanRoute=\(self.lanRouteStatus, privacy: .public)")
        }
        ipv4.includedRoutes = includedRoutes
        settings.ipv4Settings = ipv4
        settings.dnsSettings = NEDNSSettings(servers: SharedSettings.dnsServers)
        settings.mtu = 1500

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error { completionHandler(error); return }
            guard let self else { completionHandler(Self.cancelledError); return }
            self.lifecycleQueue.async {
                guard !self.stopped else { completionHandler(Self.cancelledError); return }
                self.runStart(completionHandler: completionHandler)
            }
        }
    }

    private static let cancelledError = NSError(domain: "com.mDNSShark.PacketTunnel", code: Int(ECANCELED))

    /// Runs on lifecycleQueue once the network settings are applied and stopTunnel has not run.
    private func runStart(completionHandler: @escaping (Error?) -> Void) {
        runningLock.withLock { $0 = true }

        // Clear previous session log and open a persistent write handle
        try? "".write(to: sharedFileURL, atomically: true, encoding: .utf8)
        logHandle = try? FileHandle(forWritingTo: sharedFileURL)

        var pcapReady = true
        do {
            try pcapWriter.startCapture()
        } catch {
            // PCAP unavailable (disk full, permissions) - tunnel still runs, export will fail
            pcapReady = false
        }

        let fwd = PacketForwarder(
            flow: packetFlow,
            onDecryptedHTTPS: { [weak self] payload, domain in
                self?.handleDecryptedHTTPS(payload: payload, domain: domain)
            },
            onPacket: { [weak self] rawIP, direction, isReconstructed in
                self?.handle(rawIP: rawIP, direction: direction, isReconstructed: isReconstructed)
            }
        )
        fwd.start()
        forwarder = fwd
        readLoop()
        startMDNSListener(pcapReady: pcapReady)
        completionHandler(nil)
    }

    private func readLoop() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, self.runningLock.withLock({ $0 }) else { return }
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
        lifecycleQueue.async {
            self.stopped = true
            self.runningLock.withLock { $0 = false }
            self.forwarder?.stop()
            // The listener stops first so no datagram can reach handle() after the drain below.
            self.mdnsListener?.stop()

            // Drain in-flight log writes so every appendPacket is queued before the pcap is closed and counted.
            var decryptedRequests = 0
            self.logQueue.sync {
                self.logHandle?.closeFile()
                self.logHandle = nil
                decryptedRequests = self.sequence.decryptedRequests
            }

            var meta = self.pcapWriter.stopCapture(
                deviceWiFiIP: self.lanInterfaceIPv4,
                tunnelIP: "100.64.0.1",
                decryptedRequests: decryptedRequests,
                lanRouteStatus: self.lanRouteStatus
            )
            meta["mdnsListener"] = self.mdnsListenerMeta()
            if let disclaimer = meta["disclaimer"] as? String {
                meta["disclaimer"] = disclaimer + " " + MDNSListenerMeta.disclaimerSentence
            }
            if let data = try? JSONSerialization.data(withJSONObject: meta, options: .prettyPrinted) {
                try? data.write(to: self.metaFileURL)
            }
            completionHandler()
        }
    }

    // MARK: - mDNS listener (docs/mdns-listener-scope.md section 2.3)

    /// Starts the multicast listener when the mDNS filter is on and the pcap opened; each datagram becomes a reconstructed frame through handle().
    private func startMDNSListener(pcapReady: Bool) {
        guard SharedSettings.captureFilterProtocols.contains("mDNS") else {
            setMDNSListenerStatus("disabled (mDNS filter off)")
            return
        }
        guard pcapReady else {
            setMDNSListenerStatus("not started (pcap unavailable)")
            return
        }
        let listener = BSDMDNSListener()
        mdnsListener = listener
        // Runs on the listener queue after an interface appeared or vanished; only the app-facing line changes, the session fallback stays lifecycleQueue-only.
        listener.onInterfacesChanged = { [weak self] reports in
            let summary = MDNSListenerMeta.statusSummary(reports)
            SharedSettings.mdnsListenerStatus = summary
            self?.logger.info("mDNS listener interfaces changed: \(summary, privacy: .public)")
        }
        listener.start { [weak self, weak listener] datagram, _ in
            // Either is nil only while the provider is being torn down, which is not a builder failure.
            guard let self, let listener else { return .discarded }
            guard let frame = MDNSFrameBuilder.frame(datagram) else { return .unbuildable }
            let direction: PacketDirection = listener.ownAddresses.contains(datagram.source) ? .outbound : .inbound
            self.handle(rawIP: frame, direction: direction, isReconstructed: true,
                        timestamp: datagram.timestamp, captureSource: .mdnsListener)
            return .frame
        }
        // The app's empty state keys off "listening on ...", which the summary keeps when any interface or family is listening.
        let summary = MDNSListenerMeta.statusSummary(listener.interfaces)
        setMDNSListenerStatus(summary)
        logger.info("mDNS listener: \(summary, privacy: .public)")
    }

    /// Records the session's status both for the app (SharedSettings) and for mdnsListenerMeta's fallback.
    private func setMDNSListenerStatus(_ status: String) {
        mdnsListenerStatusThisSession = status
        SharedSettings.mdnsListenerStatus = status
    }

    /// Uses the per-interface reports snapshotted inside stop() so the meta shows how the listener ran, not "stopped".
    private func mdnsListenerMeta() -> [String: Any] {
        guard let listener = mdnsListener else {
            // Without a status from this session the SharedSettings value is the previous session's, so write an explicit one.
            let status = mdnsListenerStatusThisSession ?? MDNSListenerMeta.notStartedStatus
            setMDNSListenerStatus(status)
            return MDNSListenerMeta.dictionary(notStarted: status)
        }
        return MDNSListenerMeta.dictionary(interfaces: listener.interfacesBeforeStop, stats: listener.stats)
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
