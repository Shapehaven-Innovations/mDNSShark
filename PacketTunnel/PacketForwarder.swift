// PacketTunnel/PacketForwarder.swift
import Foundation
import NetworkExtension
import Network
import os

// Called for every packet in both directions.
// rawIP: complete IPv4 packet bytes
// direction: .outbound = device→internet, .inbound = internet→device
// isReconstructed: true for stream-proxied inbound TCP
typealias PacketHandler = (_ rawIP: Data, _ direction: PacketDirection, _ isReconstructed: Bool) -> Void

final class PacketForwarder {
    private let flow: NEPacketTunnelFlow
    private let onPacket: PacketHandler
    private var sessions: [SessionKey: ActiveSession] = [:]
    private let queue = DispatchQueue(label: "com.mDNSShark.forwarder")
    private var cleanupTimer: DispatchSourceTimer?
    private var running = false
    private var tlsInterceptor: TLSInterceptor?
    private var dnsCache: [String: String] = [:]   // [destIP: hostname] from observed DNS responses
    private var onDecryptedHTTPS: ((Data, String) -> Void)?

    /// Measures per-flow relay latency (session open → first reply) without
    /// the cost or Console-attachment requirement of `os.Logger` — signposts
    /// are near-zero-cost when nothing is recording and, unlike `.debug`
    /// log lines, can be captured for later analysis via `log collect`
    /// (once `Signpost-Persisted` is set for this subsystem). Exists to
    /// answer a specific open question (todo.md item 5): does relaying LAN
    /// scan-probe traffic through this NWConnection-per-flow path add
    /// enough latency to break the device scanner's short probe timeouts.
    private let signposter = OSSignposter(subsystem: "com.mDNSShark.PacketTunnel", category: "relay")

    /// Diagnostic logging for the HTTPS-hang investigation (todo.md item 1).
    /// Lives here rather than in TLSSession because this is the only place
    /// that sees the device's *non-payload* TCP packets on an intercepted
    /// flow — the empty ACK that completes the handshake, SYN retransmits,
    /// RST/FIN — which `TLSSession.receive` never gets (it only receives
    /// payload bytes). Same subsystem as the signposter and TLSSession so a
    /// single Console filter shows everything.
    private let logger = Logger(subsystem: "com.mDNSShark.PacketTunnel", category: "forwarder")

    init(flow: NEPacketTunnelFlow,
         onDecryptedHTTPS: ((Data, String) -> Void)? = nil,
         onPacket: @escaping PacketHandler) {
        self.flow = flow
        self.onDecryptedHTTPS = onDecryptedHTTPS
        self.onPacket = onPacket
    }

    func start() {
        running = true
        if SharedSettings.tlsInspectionEnabled && !SharedSettings.tlsInspectionUnlocked {
            SharedSettings.tlsInterceptorLastError = "TLS inspection is off - unlock it in Settings"
            logger.debug("forwarder start: TLS inspection enabled but NOT unlocked — 443 flows take the plain relay path")
        } else if SharedSettings.tlsInspectionEnabled && KeychainStore.loadCAKey() != nil {
            tlsInterceptor = TLSInterceptor()
            logger.debug("forwarder start: TLSInterceptor active — 443 SYNs will be intercepted")
        } else if SharedSettings.tlsInspectionEnabled {
            SharedSettings.tlsInterceptorLastError = "TLS inspection is off - CA key not found in keychain"
            logger.debug("forwarder start: TLS inspection enabled but CA key not found in keychain (extension process) — plain relay path")
        } else {
            logger.debug("forwarder start: TLS inspection disabled — plain relay path for everything")
        }
        scheduleCleanup()
    }

    func stop() {
        running = false
        cleanupTimer?.cancel()
        tlsInterceptor?.stop()
        tlsInterceptor = nil
        queue.sync {
            // Close out any still-open relay-latency signposts before
            // discarding the sessions — without this, a flow that hadn't
            // been answered yet when capture stopped would leave its
            // interval open forever instead of recording "no reply",
            // exactly the case this instrumentation exists to catch.
            sessions.values.forEach { endSignpostIfNoReply($0); $0.connection.cancel() }
            sessions.removeAll()
        }
    }

    // Called by PacketTunnelProvider for each batch from packetFlow.readPackets
    func handleOutbound(_ packets: [Data], protocols: [NSNumber]) {
        for (i, data) in packets.enumerated() {
            guard protocols[i].int32Value == 2 /* AF_INET */ else { continue }
            onPacket(data, .outbound, false)
            route(data)
        }
    }

    // MARK: - Routing

    private func route(_ ipPacket: Data) {
        let bytes = [UInt8](ipPacket)
        guard bytes.count >= 20 else { return }
        let proto = bytes[9]
        switch proto {
        case 17: forwardUDP(ipPacket, bytes: bytes)
        case 6:  forwardTCP(ipPacket, bytes: bytes)
        default: break  // ICMP and others: no forwarding, outbound-only logging
        }
    }

    // MARK: - UDP

    private func forwardUDP(_ ipPacket: Data, bytes: [UInt8]) {
        guard bytes.count >= 28 else { return }  // 20 IP + 8 UDP minimum
        let ihl      = Int(bytes[0] & 0x0F) * 4
        let srcIP    = "\(bytes[12]).\(bytes[13]).\(bytes[14]).\(bytes[15])"
        let dstIP    = "\(bytes[16]).\(bytes[17]).\(bytes[18]).\(bytes[19])"
        let srcPort  = UInt16(bytes[ihl]) << 8 | UInt16(bytes[ihl + 1])
        let dstPort  = UInt16(bytes[ihl + 2]) << 8 | UInt16(bytes[ihl + 3])
        let payload  = ipPacket.subdata(in: (ihl + 8)..<ipPacket.count)
        let key      = SessionKey(srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, proto: 17)

        queue.async { [weak self] in
            guard let self, self.running else { return }
            let session = self.sessions[key] ?? self.createUDPSession(key: key, srcIP: srcIP, srcPort: srcPort)
            session.lastActivity = Date()
            session.connection.send(content: payload, completion: .idempotent)
        }
    }

    private func createUDPSession(key: SessionKey, srcIP: String, srcPort: UInt16) -> ActiveSession {
        let conn = NWConnection(
            host: NWEndpoint.Host(key.dstIP),
            port: NWEndpoint.Port(rawValue: key.dstPort)!,
            using: .udp
        )
        let session = ActiveSession(connection: conn, srcIP: srcIP, srcPort: srcPort)
        session.relaySignpostState = signposter.beginInterval(
            "relayFlow", id: signposter.makeSignpostID(),
            "UDP \(key.dstIP, privacy: .private):\(key.dstPort)"
        )
        sessions[key] = session

        conn.stateUpdateHandler = { [weak self, weak session] state in
            if case .failed = state {
                self?.queue.async {
                    guard let self, let session else { return }
                    self.removeSessionIfCurrent(key: key, session: session)
                }
            }
        }

        receiveUDP(conn: conn, key: key, srcIP: srcIP, srcPort: srcPort)
        conn.start(queue: queue)
        return session
    }

    private func receiveUDP(conn: NWConnection, key: SessionKey, srcIP: String, srcPort: UInt16) {
        conn.receiveMessage { [weak self] content, _, _, error in
            guard let self, self.running, let payload = content, !payload.isEmpty else { return }
            let responsePacket = self.buildIPv4UDPPacket(
                srcIP: key.dstIP, dstIP: srcIP,
                srcPort: key.dstPort, dstPort: srcPort,
                payload: payload
            )
            self.flow.writePackets([responsePacket], withProtocols: [NSNumber(value: AF_INET)])
            self.onPacket(responsePacket, .inbound, false)
            // Cache IP→hostname mappings from DNS responses for TLS bypass list
            if key.dstPort == 53 || key.srcPort == 53 {
                self.cacheDNSResponse(payload)
            }
            self.queue.async {
                guard let session = self.sessions[key] else { return }
                session.lastActivity = Date()
                if !session.firstReplyRecorded, let state = session.relaySignpostState {
                    session.firstReplyRecorded = true
                    self.signposter.endInterval("relayFlow", state)
                }
            }
            // recurse to keep receiving
            self.receiveUDP(conn: conn, key: key, srcIP: srcIP, srcPort: srcPort)
        }
    }

    // MARK: - TCP

    private func forwardTCP(_ ipPacket: Data, bytes: [UInt8]) {
        guard bytes.count >= 40 else { return }  // 20 IP + 20 TCP minimum
        let ihl     = Int(bytes[0] & 0x0F) * 4
        let srcIP   = "\(bytes[12]).\(bytes[13]).\(bytes[14]).\(bytes[15])"
        let dstIP   = "\(bytes[16]).\(bytes[17]).\(bytes[18]).\(bytes[19])"
        let srcPort = UInt16(bytes[ihl])     << 8 | UInt16(bytes[ihl + 1])
        let dstPort = UInt16(bytes[ihl + 2]) << 8 | UInt16(bytes[ihl + 3])
        let tcpFlags = bytes[ihl + 13]
        let dataOffset = Int(bytes[ihl + 12] >> 4) * 4
        let payloadStart = ihl + dataOffset
        let key = SessionKey(srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, proto: 6)
        // tcpAck is only read by the diagnostic log lines below; tcpSeq is
        // also passed to interceptor.deliver so TLSSession can detect
        // retransmits/reordering instead of blindly trusting payload order.
        let tcpSeq = UInt32(bytes[ihl+4]) << 24 | UInt32(bytes[ihl+5]) << 16
                   | UInt32(bytes[ihl+6]) << 8  | UInt32(bytes[ihl+7])
        let tcpAck = UInt32(bytes[ihl+8]) << 24 | UInt32(bytes[ihl+9]) << 16
                   | UInt32(bytes[ihl+10]) << 8 | UInt32(bytes[ihl+11])

        let payload = payloadStart < ipPacket.count
            ? ipPacket.subdata(in: payloadStart..<ipPacket.count)
            : Data()

        queue.async { [weak self] in
            guard let self, self.running else { return }

            let isFIN = tcpFlags & 0x01 != 0
            let isRST = tcpFlags & 0x04 != 0
            let isSYN = tcpFlags & 0x02 != 0

            // If this session is owned by TLSInterceptor, deliver data there.
            if let interceptor = self.tlsInterceptor, interceptor.hasSession(for: key) {
                let flowTag = "\(srcIP):\(srcPort)→\(dstIP):\(dstPort)"
                if isFIN || isRST {
                    // RST right after our SYN-ACK = the device's TCP stack
                    // received the SYN-ACK (so checksums passed) but rejected
                    // it (bad ack number, or no listening socket anymore).
                    // RST/FIN minutes later = the device's own timer gave up.
                    self.logger.debug("[\(flowTag, privacy: .public)] device sent \(isRST ? "RST" : "FIN", privacy: .public) flags=0x\(String(tcpFlags, radix: 16), privacy: .public) seq=\(tcpSeq) ack=\(tcpAck) — closing intercept session")
                    interceptor.closeSession(for: key)
                } else if isSYN {
                    // A repeated SYN on a key that already has a session means
                    // the device never accepted our SYN-ACK and is retrying
                    // the handshake — the checksum (or something else in the
                    // synthetic packet) is still being rejected. Previously
                    // only logged, never retried, so a rejected SYN-ACK left
                    // the flow permanently wedged even after fixes (checksum,
                    // MSS) that would have made a retry succeed.
                    self.logger.debug("[\(flowTag, privacy: .public)] device RETRANSMITTED SYN (isn=\(tcpSeq)) — resending SYN-ACK")
                    interceptor.resendSYNACK(for: key)
                } else if !payload.isEmpty {
                    interceptor.deliver(payload, seq: tcpSeq, for: key)
                } else {
                    // Pure ACK. The first one is the handshake's third packet —
                    // direct proof the SYN-ACK was accepted even if Safari
                    // never sends a ClientHello. Later ones show how far the
                    // device has acknowledged our data (compare `ack` against
                    // the seq in TLSSession's "first write to device" line).
                    self.logger.debug("[\(flowTag, privacy: .public)] device pure ACK flags=0x\(String(tcpFlags, radix: 16), privacy: .public) seq=\(tcpSeq) ack=\(tcpAck)")
                }
                return
            }

            // Plain relay never sends a SYN-ACK, so any SYN reaching it for
            // a web port will hang from the device's point of view. Logged
            // for 80/443 only: a port-80 SYN appearing right after Safari's
            // "Continue" tap is Safari's HTTPS→HTTP fallback; a 443 SYN here
            // means the interceptor is nil or the dnsCache bypass matched.
            if isSYN && self.sessions[key] == nil && (dstPort == 80 || dstPort == 443) {
                self.logger.debug("[\(srcIP, privacy: .public):\(srcPort)→\(dstIP, privacy: .public):\(dstPort)] SYN on plain relay path (no SYN-ACK is ever sent here) interceptorActive=\(self.tlsInterceptor != nil)")
            }

            if isFIN || isRST {
                if let s = self.sessions[key] { self.endSignpostIfNoReply(s) }
                self.sessions[key]?.connection.cancel()
                self.sessions.removeValue(forKey: key)
                return
            }

            if isSYN && self.sessions[key] == nil {
                if self.dstPort443Intercepted(key: key, srcIP: srcIP, bytes: bytes, ipPacket: ipPacket) {
                    return
                }
                self.createTCPSession(key: key, srcIP: srcIP, srcPort: srcPort)
            }

            guard let session = self.sessions[key], !payload.isEmpty else { return }
            session.lastActivity = Date()
            session.connection.send(content: payload, completion: .idempotent)
        }
    }

    private func dstPort443Intercepted(key: SessionKey, srcIP: String,
                                        bytes: [UInt8], ipPacket: Data) -> Bool {
        guard key.dstPort == 443, let interceptor = tlsInterceptor else { return false }
        // IP-level bypass: check if we've seen this IP resolve to a bypassed hostname
        if let hostname = dnsCache[key.dstIP],
           SharedSettings.tlsBypassList.contains(where: { hostname.hasSuffix($0) }) {
            logger.debug("[\(srcIP, privacy: .public):\(key.srcPort)→\(key.dstIP, privacy: .public):443] not intercepting: dnsCache says \(hostname, privacy: .public) is bypassed")
            return false
        }
        // Extract client ISN from the SYN packet (sequence number field in TCP header)
        let ihl = Int(bytes[0] & 0x0F) * 4
        let clientISN = UInt32(bytes[ihl+4]) << 24 | UInt32(bytes[ihl+5]) << 16
                      | UInt32(bytes[ihl+6]) << 8  | UInt32(bytes[ihl+7])
        logger.debug("[\(srcIP, privacy: .public):\(key.srcPort)→\(key.dstIP, privacy: .public):443] intercepting SYN isn=\(clientISN) dnsCache=\(self.dnsCache[key.dstIP] ?? "<no DNS seen for this IP>", privacy: .public)")
        interceptor.openSession(
            key: key, srcIP: srcIP, dstIP: key.dstIP,
            clientISN: clientISN, flow: flow,
            onDecryptedRequest: onDecryptedHTTPS ?? { _, _ in }
        )
        return true
    }

    private func createTCPSession(key: SessionKey, srcIP: String, srcPort: UInt16) {
        let conn = NWConnection(
            host: NWEndpoint.Host(key.dstIP),
            port: NWEndpoint.Port(rawValue: key.dstPort)!,
            using: .tcp
        )
        let session = ActiveSession(connection: conn, srcIP: srcIP, srcPort: srcPort)
        session.relaySignpostState = signposter.beginInterval(
            "relayFlow", id: signposter.makeSignpostID(),
            "TCP \(key.dstIP, privacy: .private):\(key.dstPort)"
        )
        sessions[key] = session

        conn.stateUpdateHandler = { [weak self, weak session] state in
            switch state {
            case .failed, .cancelled:
                self?.queue.async {
                    guard let self, let session else { return }
                    self.removeSessionIfCurrent(key: key, session: session)
                }
            default: break
            }
        }

        receiveTCP(conn: conn, key: key, srcIP: srcIP, srcPort: srcPort, session: session)
        conn.start(queue: queue)
    }

    private func receiveTCP(conn: NWConnection, key: SessionKey,
                            srcIP: String, srcPort: UInt16, session: ActiveSession) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65535) { [weak self] content, _, isComplete, error in
            guard let self, self.running else { return }
            if let payload = content, !payload.isEmpty {
                let responsePacket = self.buildIPv4TCPPacket(
                    srcIP: key.dstIP, dstIP: srcIP,
                    srcPort: key.dstPort, dstPort: srcPort,
                    payload: payload, seq: session.seqCounter
                )
                session.seqCounter &+= UInt32(payload.count)
                self.flow.writePackets([responsePacket], withProtocols: [NSNumber(value: AF_INET)])
                self.onPacket(responsePacket, .inbound, true)  // isReconstructed = true for TCP
                self.queue.async {
                    session.lastActivity = Date()
                    if !session.firstReplyRecorded, let state = session.relaySignpostState {
                        session.firstReplyRecorded = true
                        self.signposter.endInterval("relayFlow", state)
                    }
                }
            }
            if !isComplete && error == nil {
                self.receiveTCP(conn: conn, key: key, srcIP: srcIP, srcPort: srcPort, session: session)
            } else {
                self.queue.async {
                    self.removeSessionIfCurrent(key: key, session: session)
                }
            }
        }
    }

    // MARK: - Packet construction

    // Both builders below patch in real IPv4 header + UDP/TCP checksums —
    // previously left as 0x0000. TLSInterceptor.swift's synthetic packets had
    // the same defect and fixing it there is what got a real device to accept
    // a synthetic SYN-ACK at all; this plain relay path builds packets the
    // same way (raw bytes into flow.writePackets) and was never fixed
    // alongside it. UDP's own checksum field is spec-allowed to be zero
    // ("no checksum computed", RFC 768) and this relay evidently still works
    // for UDP without it (DNS through it has been observed working), but the
    // IPv4 header checksum has no such allowance, and a real checksum is
    // never wrong to send. TCP's seq(approx)/ack(0, approx) semantics are
    // unchanged here — that's the separate, larger, not-yet-fixed handshake
    // gap tracked in todo.md item 1, out of scope for a checksum fix.
    private func buildIPv4UDPPacket(srcIP: String, dstIP: String,
                                     srcPort: UInt16, dstPort: UInt16,
                                     payload: Data) -> Data {
        let udpLen  = UInt16(8 + payload.count)
        let totalLen = UInt16(20 + udpLen)
        var p = Data(capacity: Int(totalLen))
        // IPv4 header
        p.append(0x45)                      // version=4, IHL=5 (20 bytes)
        p.append(0x00)                      // DSCP/ECN
        p.appendBE16(totalLen)
        p.appendBE16(0x0000)                // ID
        p.appendBE16(0x4000)                // Don't fragment
        p.append(64)                        // TTL
        p.append(17)                        // protocol: UDP
        p.appendBE16(0x0000)               // IP header checksum, patched below
        p.append(ipOctets: srcIP)
        p.append(ipOctets: dstIP)
        // UDP header
        p.appendBE16(srcPort)
        p.appendBE16(dstPort)
        p.appendBE16(udpLen)
        p.appendBE16(0x0000)               // UDP checksum, patched below
        p.append(payload)

        var bytes = [UInt8](p)
        let ipChecksum = PacketChecksum.internetChecksum(bytes[0..<20])
        bytes[10] = UInt8(ipChecksum >> 8); bytes[11] = UInt8(ipChecksum & 0xFF)

        var pseudoHeader = PacketChecksum.ipv4Bytes(srcIP) + PacketChecksum.ipv4Bytes(dstIP)
        pseudoHeader += [0x00, 17]
        pseudoHeader += [UInt8(udpLen >> 8), UInt8(udpLen & 0xFF)]
        var udpChecksum = PacketChecksum.internetChecksum(pseudoHeader + bytes[20...])
        if udpChecksum == 0x0000 { udpChecksum = 0xFFFF }  // RFC 768: 0 means "no checksum"
        bytes[26] = UInt8(udpChecksum >> 8); bytes[27] = UInt8(udpChecksum & 0xFF)

        return Data(bytes)
    }

    private func buildIPv4TCPPacket(srcIP: String, dstIP: String,
                                     srcPort: UInt16, dstPort: UInt16,
                                     payload: Data, seq: UInt32) -> Data {
        let tcpLen   = UInt16(20 + payload.count)
        let totalLen = UInt16(20 + tcpLen)
        var p = Data(capacity: Int(totalLen))
        // IPv4 header
        p.append(0x45)
        p.append(0x00)
        p.appendBE16(totalLen)
        p.appendBE16(0x0000)
        p.appendBE16(0x4000)
        p.append(64)
        p.append(6)                         // protocol: TCP
        p.appendBE16(0x0000)               // IP header checksum, patched below
        p.append(ipOctets: srcIP)
        p.append(ipOctets: dstIP)
        // TCP header
        p.appendBE16(srcPort)
        p.appendBE16(dstPort)
        p.appendBE32(seq)                   // sequence number (approx)
        p.appendBE32(0)                     // ack number (approx)
        p.append(0x50)                      // data offset = 5 (20 bytes)
        p.append(0x18)                      // flags: PSH + ACK
        p.appendBE16(65535)                 // window size
        p.appendBE16(0x0000)               // TCP checksum, patched below
        p.appendBE16(0x0000)               // urgent pointer
        p.append(payload)

        var bytes = [UInt8](p)
        let ipChecksum = PacketChecksum.internetChecksum(bytes[0..<20])
        bytes[10] = UInt8(ipChecksum >> 8); bytes[11] = UInt8(ipChecksum & 0xFF)

        var pseudoHeader = PacketChecksum.ipv4Bytes(srcIP) + PacketChecksum.ipv4Bytes(dstIP)
        pseudoHeader += [0x00, 6]
        pseudoHeader += [UInt8(tcpLen >> 8), UInt8(tcpLen & 0xFF)]
        let tcpChecksum = PacketChecksum.internetChecksum(pseudoHeader + bytes[20...])
        bytes[36] = UInt8(tcpChecksum >> 8); bytes[37] = UInt8(tcpChecksum & 0xFF)

        return Data(bytes)
    }

    private func cacheDNSResponse(_ udpPayload: Data) {
        guard udpPayload.count > 8 else { return }
        let dns = [UInt8](udpPayload.dropFirst(8))
        guard dns.count > 12 else { return }
        let qdCount = Int(dns[4]) << 8 | Int(dns[5])
        let anCount = Int(dns[6]) << 8 | Int(dns[7])
        guard anCount > 0 else { return }
        var i = 12
        for _ in 0..<qdCount {
            while i < dns.count { let len = Int(dns[i]); i += 1; if len == 0 { break }; i += len }
            i += 4
        }
        for _ in 0..<anCount {
            guard i < dns.count else { break }
            let hostname = parseDNSName(dns, at: &i)
            guard i + 10 <= dns.count else { break }
            let rtype = Int(dns[i]) << 8 | Int(dns[i+1])
            let rdLen = Int(dns[i+8]) << 8 | Int(dns[i+9])
            i += 10
            if rtype == 1 && rdLen == 4 && i + 4 <= dns.count {
                let ip = "\(dns[i]).\(dns[i+1]).\(dns[i+2]).\(dns[i+3])"
                dnsCache[ip] = hostname
            }
            i += rdLen
        }
    }

    private func parseDNSName(_ dns: [UInt8], at i: inout Int) -> String {
        var labels = [String]()
        while i < dns.count {
            let len = Int(dns[i])
            if len == 0 { i += 1; break }
            if len & 0xC0 == 0xC0 { i += 2; break }
            i += 1
            guard i + len <= dns.count else { break }
            labels.append(String(bytes: dns[i..<i+len], encoding: .utf8) ?? "")
            i += len
        }
        return labels.joined(separator: ".")
    }

    // MARK: - Cleanup

    private func scheduleCleanup() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 60, repeating: 60)
        t.setEventHandler { [weak self] in
            self?.removeIdleSessions()
            self?.reevaluateTLSAccess()
        }
        t.resume()
        cleanupTimer = t
    }

    // Entitlement can be revoked (trial expiry, refund) while the tunnel keeps
    // running for hours/days, so re-check alongside the existing 60s cleanup tick
    // instead of trusting the one-time check in start().
    private func reevaluateTLSAccess() {
        guard SharedSettings.tlsInspectionEnabled else { return }
        if !SharedSettings.tlsInspectionUnlocked {
            if tlsInterceptor != nil {
                tlsInterceptor?.stop()
                tlsInterceptor = nil
                SharedSettings.tlsInterceptorLastError = "TLS inspection is off - unlock it in Settings"
            }
        } else if tlsInterceptor == nil && KeychainStore.loadCAKey() != nil {
            tlsInterceptor = TLSInterceptor()
        }
    }

    private func removeIdleSessions() {
        let cutoff = Date().addingTimeInterval(-60)
        sessions = sessions.filter { _, session in
            if session.lastActivity < cutoff {
                endSignpostIfNoReply(session)
                session.connection.cancel()
                return false
            }
            return true
        }
    }

    /// Closes a session's relay-latency signpost interval when it's torn
    /// down without ever getting a reply relayed back (idle timeout,
    /// connection failure, or the peer closing first) — the counterpart to
    /// the normal close in `receiveUDP`/`receiveTCP`. Without this, a
    /// never-answered flow (exactly the case this instrumentation exists to
    /// catch — e.g. a scan probe that times out) would leave its interval
    /// open forever instead of recording "no reply within N seconds".
    private func endSignpostIfNoReply(_ session: ActiveSession) {
        guard !session.firstReplyRecorded, let state = session.relaySignpostState else { return }
        session.firstReplyRecorded = true
        signposter.endInterval("relayFlow", state, "no reply")
    }

    /// Removes `key`'s entry only if it still points at `session` — a delayed
    /// teardown callback for an old flow must never evict a new flow that has
    /// since reclaimed the same 4-tuple key.
    private func removeSessionIfCurrent(key: SessionKey, session: ActiveSession) {
        guard sessions[key] === session else { return }
        endSignpostIfNoReply(session)
        sessions.removeValue(forKey: key)
    }
}

// MARK: - Supporting types

struct SessionKey: Hashable {
    let srcPort: UInt16
    let dstIP: String
    let dstPort: UInt16
    let proto: UInt8
}

final class ActiveSession {
    let connection: NWConnection
    let srcIP: String
    let srcPort: UInt16
    var lastActivity: Date = Date()
    var seqCounter: UInt32 = 1000  // approximate, for TCP reconstruction

    /// Signpost interval covering "session opened" → "first reply relayed
    /// back to the device". Ended once, on the first reply only — a
    /// long-lived session (e.g. a kept-alive TCP connection) would otherwise
    /// keep re-measuring the same already-answered interval on every
    /// subsequent packet.
    var relaySignpostState: OSSignpostIntervalState?
    var firstReplyRecorded = false

    init(connection: NWConnection, srcIP: String, srcPort: UInt16) {
        self.connection = connection
        self.srcIP = srcIP
        self.srcPort = srcPort
    }
}

// MARK: - Data helpers (big-endian for IP/TCP/UDP headers)
extension Data {
    mutating func appendBE16(_ v: UInt16) {
        var x = v.bigEndian; append(Data(bytes: &x, count: MemoryLayout<UInt16>.size))
    }
    mutating func appendBE32(_ v: UInt32) {
        var x = v.bigEndian; append(Data(bytes: &x, count: MemoryLayout<UInt32>.size))
    }
    mutating func append(ipOctets ip: String) {
        ip.split(separator: ".").compactMap { UInt8($0) }.forEach { append($0) }
    }
}
