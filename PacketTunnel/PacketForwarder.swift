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
    /// the cost or Console-attachment requirement of `os.Logger`: signposts
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
    /// flow: the empty ACK that completes the handshake, SYN retransmits,
    /// RST/FIN. `TLSSession.receive` never sees those (it only receives
    /// payload bytes). Same subsystem as the signposter and TLSSession so a
    /// single Console filter shows everything. Also used by the plain-relay
    /// TCP path below for the same class of diagnostics.
    private let logger = Logger(subsystem: "com.mDNSShark.PacketTunnel", category: "forwarder")

    // MSS advertised in the plain-relay path's synthetic SYN-ACK, and the
    // ceiling used to chunk any real-destination reply before it goes back
    // to the device. Same value and same reasoning as
    // TLSSession.advertisedMSS in TLSInterceptor.swift: without it the
    // device's kernel falls back to a 512-byte default, and a single
    // oversized synthetic segment silently violates both the MSS we
    // advertised and the tunnel's MTU (the device's kernel just never acks
    // it).
    private static let advertisedMSS = 1460
    private static let mssOption = Data([0x02, 0x04, 0x05, 0xB4])

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
            logger.debug("forwarder start: TLS inspection enabled but NOT unlocked; 443 flows take the plain relay path")
        } else if SharedSettings.tlsInspectionEnabled && TLSInterceptor.hasCompleteCAIdentity() {
            tlsInterceptor = TLSInterceptor(onPacket: onPacket)
            logger.debug("forwarder start: TLSInterceptor active: 443 SYNs will be intercepted")
        } else if SharedSettings.tlsInspectionEnabled {
            SharedSettings.tlsInterceptorLastError = "TLS inspection is off - CA key/cert not found in keychain"
            logger.debug("forwarder start: TLS inspection enabled but no complete CA key+cert pair in keychain (extension process); plain relay path")
        } else {
            logger.debug("forwarder start: TLS inspection disabled; plain relay path for everything")
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
            // discarding the sessions. Without this, a flow that hadn't
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

            // QUIC/HTTP-3 runs over UDP:443 by convention and is plain UDP
            // to this relay; TLSInterceptor never sees it. Whenever a
            // client can use it, it races against our TLS-intercepted TCP
            // path and wins almost every time (QUIC needs no synthetic
            // handshake, no local listener/bridge, no separate upstream TLS
            // negotiation), so TLS Inspection silently inspects nothing for
            // QUIC-capable destinations. Confirmed on-device:
            // accounts.google.com's TCP+TLS attempt got cancelled ~115ms
            // after its ClientHello, right as a parallel QUIC connection to
            // the same IP finished its own handshake. Dropping UDP:443
            // outright (silently, no ICMP/rejection) while interception
            // can actually happen forces the QUIC-to-TCP fallback every
            // real HTTP/3 client already implements for exactly this
            // "middlebox silently drops UDP" case; the same technique real
            // TLS-inspecting proxies use. Gated on tlsInterceptor being
            // non-nil (checked here, same as forwardTCP, since it's only
            // mutated on this queue), not just the settings toggle, so this
            // never fires unless interception can actually happen.
            if dstPort == 443, self.tlsInterceptor != nil { return }

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
            let isSYN = tcpFlags & 0x02 != 0
            let isRST = tcpFlags & 0x04 != 0
            let isACK = tcpFlags & 0x10 != 0

            // If this session is owned by TLSInterceptor, deliver data there.
            if let interceptor = self.tlsInterceptor, interceptor.hasSession(for: key) {
                let flowTag = "\(srcIP):\(srcPort)→\(dstIP):\(dstPort)"
                if isFIN || isRST {
                    // Darwin's TCP stack routinely coalesces a final write
                    // with the FIN into one segment (write-then-close), so
                    // this branch being checked ahead of the payload one
                    // below must not just drop that payload: it's often the
                    // last chunk of a request/response. And the FIN's own
                    // sequence number in that case is tcpSeq + payload.count,
                    // not tcpSeq itself (the FIN consumes the sequence slot
                    // right after the data, same as a bare FIN consumes the
                    // slot it's sent at). Passing bare tcpSeq here acked one
                    // segment short of what the device's kernel expects,
                    // reproducing the same "device retransmits its FIN
                    // forever" bug deviceFINSeq was added to fix, just for
                    // the coalesced case instead of the bare-FIN one.
                    if !payload.isEmpty {
                        interceptor.deliver(payload, seq: tcpSeq, for: key)
                    }
                    let finSeq = tcpSeq &+ UInt32(payload.count)
                    // RST right after our SYN-ACK = the device's TCP stack
                    // received the SYN-ACK (so checksums passed) but rejected
                    // it (bad ack number, or no listening socket anymore).
                    // RST/FIN minutes later = the device's own timer gave up.
                    self.logger.debug("[\(flowTag, privacy: .public)] device sent \(isRST ? "RST" : "FIN", privacy: .public) flags=0x\(String(tcpFlags, radix: 16), privacy: .public) seq=\(tcpSeq) ack=\(tcpAck) payload=\(payload.count); closing intercept session")
                    interceptor.closeSession(for: key, deviceFINSeq: isFIN ? finSeq : nil)
                } else if isSYN {
                    // A repeated SYN on a key that already has a session means
                    // the device never accepted our SYN-ACK and is retrying
                    // the handshake: the checksum (or something else in the
                    // synthetic packet) is still being rejected. Previously
                    // only logged, never retried, so a rejected SYN-ACK left
                    // the flow permanently wedged even after fixes (checksum,
                    // MSS) that would have made a retry succeed.
                    self.logger.debug("[\(flowTag, privacy: .public)] device RETRANSMITTED SYN (isn=\(tcpSeq)); resending SYN-ACK")
                    interceptor.resendSYNACK(for: key)
                } else if !payload.isEmpty {
                    interceptor.deliver(payload, seq: tcpSeq, for: key)
                } else {
                    // Pure ACK. The first one is the handshake's third packet:
                    // direct proof the SYN-ACK was accepted even if Safari
                    // never sends a ClientHello. Later ones show how far the
                    // device has acknowledged our data (compare `ack` against
                    // the seq in TLSSession's "first write to device" line).
                    self.logger.debug("[\(flowTag, privacy: .public)] device pure ACK flags=0x\(String(tcpFlags, radix: 16), privacy: .public) seq=\(tcpSeq) ack=\(tcpAck)")
                }
                return
            }

            // Plain relay path: a real client-side TCP session, driven by
            // ActiveSession's clientSeq/serverSeq (todo.md item 1). See
            // completeHandshake/closeTCPSession below for why the SYN-ACK
            // is deferred and how teardown mirrors TLSSession.close().
            if let session = self.sessions[key] {
                if session.torndown {
                    // Already closed; left in `sessions` briefly (reaped by
                    // the 60s idle sweep) instead of removed immediately, so
                    // the tail end of a close — the device's own closing
                    // ACK/FIN crossing on the wire — is silently absorbed
                    // instead of looking like an unknown session and
                    // drawing a spurious RST. Confirmed on-device: every
                    // clean plain-relay close ended with an extra RST/RST
                    // pair after an otherwise normal FIN/FIN/ACK exchange
                    // before this fix. Only a genuinely new SYN (a
                    // different ISN — e.g. a scanner restarting a probe on
                    // the same ephemeral source port before the old entry
                    // ages out) starts a fresh session here.
                    if isSYN, tcpSeq != session.clientISN {
                        if self.dstPort443Intercepted(key: key, srcIP: srcIP, bytes: bytes, ipPacket: ipPacket) { return }
                        self.createTCPSession(key: key, srcIP: srcIP, srcPort: srcPort, clientISN: tcpSeq)
                        return
                    }
                    // A relay-initiated close (real destination EOF, sent
                    // our own FIN) leaves this session torndown while the
                    // device may still be mid-close on its own side — its
                    // closing FIN (or a last data segment) can legitimately
                    // arrive after our teardown ran, same as the
                    // simultaneous-close case `closeTCPSession`'s
                    // `deviceFINSeq` parameter already handles when it
                    // arrives *before* teardown. Absorbing it here with no
                    // ack (as an RST-closed session correctly does — the
                    // device already got a definitive answer) instead left
                    // the device's kernel retransmitting its FIN for ~15-18s
                    // before giving up, the exact failure
                    // `TLSSession.close(deviceFINSeq:)` in
                    // TLSInterceptor.swift was built to avoid. The
                    // underlying relay connection is already cancelled, so
                    // this ack is pure protocol courtesy, not data
                    // delivery — there's nothing left to forward it to.
                    guard session.closedGracefully, !isRST else { return }
                    let consumed = UInt32(payload.count) &+ (isFIN ? 1 : 0)
                    if tcpSeq == session.clientSeq {
                        session.clientSeq = session.clientSeq &+ consumed
                    }
                    self.sendControlPacket(session: session, key: key, srcIP: srcIP, srcPort: srcPort, flags: 0x10)
                    return
                }

                session.lastActivity = Date()

                if isRST {
                    self.closeTCPSession(session, key: key, srcIP: srcIP, srcPort: srcPort, notifyDevice: false)
                    return
                }

                if isSYN {
                    if tcpSeq != session.clientISN {
                        // A new logical connection reusing this session's
                        // 4-tuple before it was cleaned up — not a
                        // retransmit of the existing one, since its ISN
                        // doesn't match. Tear the stale session down (RST
                        // if the device had already been told it was open)
                        // and start fresh instead of resending a stale
                        // SYN-ACK for a connection the device never asked
                        // for.
                        self.closeTCPSession(session, key: key, srcIP: srcIP, srcPort: srcPort,
                                              sendReset: session.handshakeCompleted)
                        if self.dstPort443Intercepted(key: key, srcIP: srcIP, bytes: bytes, ipPacket: ipPacket) { return }
                        self.createTCPSession(key: key, srcIP: srcIP, srcPort: srcPort, clientISN: tcpSeq)
                        return
                    }
                    // Device retransmitted its SYN. If our own SYN-ACK
                    // already went out, resend that exact one (a different
                    // seq on retry is itself a protocol violation the
                    // device's kernel would reject). If the relay's own
                    // NWConnection to the real destination hasn't reached
                    // .ready yet, do nothing: sending a SYN-ACK now, before
                    // we know the real destination is reachable, is exactly
                    // the phantom-open bug this design avoids.
                    // completeHandshake sends the real SYN-ACK once .ready
                    // actually happens.
                    if session.handshakeCompleted, let synAckSeq = session.synAckSeq {
                        self.logger.debug("[\(srcIP, privacy: .public):\(srcPort)→\(dstIP, privacy: .public):\(dstPort)] device RETRANSMITTED SYN; resending SYN-ACK")
                        self.sendSYNACK(session: session, key: key, srcIP: srcIP, srcPort: srcPort,
                                         seq: synAckSeq, ack: session.clientSeq)
                    }
                    return
                }

                // The device shouldn't send data/FIN before our SYN-ACK
                // (it's still waiting on the handshake); drop rather than
                // acting on sequence numbers that aren't set up yet.
                guard session.handshakeCompleted else { return }

                if isFIN {
                    self.handleDeviceFIN(session: session, key: key, srcIP: srcIP, srcPort: srcPort,
                                          tcpSeq: tcpSeq, payload: payload)
                } else if !payload.isEmpty {
                    self.handleDeviceData(session: session, key: key, srcIP: srcIP, srcPort: srcPort,
                                           tcpSeq: tcpSeq, payload: payload)
                }
                return
            }

            // No session for this key.
            if isRST { return }  // never reset a reset

            if isSYN {
                if self.dstPort443Intercepted(key: key, srcIP: srcIP, bytes: bytes, ipPacket: ipPacket) {
                    return
                }
                self.createTCPSession(key: key, srcIP: srcIP, srcPort: srcPort, clientISN: tcpSeq)
                return
            }

            // Any other packet (data, FIN, or a pure ACK) on an unknown or
            // already-closed session: previously silently dropped, leaving
            // the device to retry until its own timeout gave up. RFC 9293
            // §3.10.7.1's reset-generation rule gives a definitive answer
            // instead: if the incoming segment carries ACK, RST's seq is
            // that ack value with no ACK of our own; otherwise RST is sent
            // as seq=0, ack=(their seq + however many sequence numbers
            // their segment consumed), with ACK set.
            let consumed = UInt32(payload.count) &+ (isFIN ? 1 : 0)
            self.sendRFC793Reset(key: key, srcIP: srcIP, srcPort: srcPort,
                                  incomingSeq: tcpSeq, incomingAck: tcpAck,
                                  incomingHasACK: isACK, consumed: consumed)
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

    private func createTCPSession(key: SessionKey, srcIP: String, srcPort: UInt16, clientISN: UInt32) {
        let conn = NWConnection(
            host: NWEndpoint.Host(key.dstIP),
            port: NWEndpoint.Port(rawValue: key.dstPort)!,
            using: .tcp
        )
        let session = ActiveSession(connection: conn, srcIP: srcIP, srcPort: srcPort)
        session.clientISN = clientISN
        session.relaySignpostState = signposter.beginInterval(
            "relayFlow", id: signposter.makeSignpostID(),
            "TCP \(key.dstIP, privacy: .private):\(key.dstPort)"
        )
        sessions[key] = session

        conn.stateUpdateHandler = { [weak self, weak session] state in
            guard let self, let session else { return }
            switch state {
            case .ready:
                self.completeHandshake(session: session, key: key, srcIP: srcIP, srcPort: srcPort)
            case .failed, .waiting:
                // LAN connection-refused arrives as .waiting on
                // Network.framework, not .failed; either one means the
                // relay's own connection to the real destination will never
                // open, so tell the device now via RST instead of leaving
                // it to retransmit its SYN until its own timeout gives up.
                guard self.sessions[key] === session else { return }
                self.logger.debug("[\(srcIP, privacy: .public):\(srcPort)→\(key.dstIP, privacy: .public):\(key.dstPort)] relay connection \(String(describing: state), privacy: .public); sending RST to device")
                self.closeTCPSession(session, key: key, srcIP: srcIP, srcPort: srcPort, sendReset: true)
            case .cancelled:
                // Defensive: NWConnection.cancelled should only ever follow
                // one of our own connection.cancel() calls, already routed
                // through closeTCPSession elsewhere (a no-op here then,
                // since torndown is already true by the time this fires).
                // But if the OS ever cancels the connection directly
                // without going through .failed/.waiting first, this is the
                // only place left to notice and clean the entry up, rather
                // than leaking it until the 60s idle sweep.
                guard self.sessions[key] === session else { return }
                self.closeTCPSession(session, key: key, srcIP: srcIP, srcPort: srcPort, sendReset: true)
            default: break
            }
        }

        receiveTCP(conn: conn, key: key, srcIP: srcIP, srcPort: srcPort, session: session)
        conn.start(queue: queue)
    }

    /// Sends the device's real SYN-ACK once (and only once) the relay's own
    /// `NWConnection` to the real destination reaches `.ready`. This is the
    /// deferred-handshake design the fable review required: `TLSSession`'s
    /// device is always our own MITM listener (always ready), but here the
    /// "device" the SYN-ACK vouches for is the real destination on the LAN
    /// or internet. Sending it before `.ready` would turn every
    /// filtered/dropped port into a phantom "open" result instead of
    /// today's "nothing shows" — worse, not better.
    private func completeHandshake(session: ActiveSession, key: SessionKey, srcIP: String, srcPort: UInt16) {
        guard sessions[key] === session, !session.handshakeCompleted, !session.torndown else { return }
        session.handshakeCompleted = true
        let seq = session.serverSeq
        session.synAckSeq = seq
        session.clientSeq = session.clientISN &+ 1
        session.serverSeq = seq &+ 1   // SYN consumes one sequence number
        sendSYNACK(session: session, key: key, srcIP: srcIP, srcPort: srcPort, seq: seq, ack: session.clientSeq)
    }

    private func sendSYNACK(session: ActiveSession, key: SessionKey, srcIP: String, srcPort: UInt16,
                             seq: UInt32, ack: UInt32) {
        let packet = buildIPv4TCPPacket(
            srcIP: key.dstIP, dstIP: srcIP,
            srcPort: key.dstPort, dstPort: srcPort,
            seq: seq, ack: ack, flags: 0x12, payload: Data(),
            options: Self.mssOption
        )
        flow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
        onPacket(packet, .inbound, true)
        logger.debug("[\(srcIP, privacy: .public):\(srcPort)→\(key.dstIP, privacy: .public):\(key.dstPort)] sendSYNACK seq=\(seq) ack=\(ack) mss=1460")
    }

    /// A control packet (pure ACK, FIN+ACK, or RST) sent using the session's
    /// live seq/ack state — only valid once `handshakeCompleted`. Mirrors
    /// the ack packets `TLSSession.receive`/`close` build in
    /// TLSInterceptor.swift.
    private func sendControlPacket(session: ActiveSession, key: SessionKey, srcIP: String, srcPort: UInt16,
                                    flags: UInt8) {
        let packet = buildIPv4TCPPacket(
            srcIP: key.dstIP, dstIP: srcIP,
            srcPort: key.dstPort, dstPort: srcPort,
            seq: session.serverSeq, ack: session.clientSeq,
            flags: flags, payload: Data()
        )
        flow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
        onPacket(packet, .inbound, true)
    }

    /// RFC 9293 §3.10.7.1 reset generation for a segment that has no
    /// matching session at all (never existed, or already torn down) and
    /// for a pre-handshake connection failure (no SYN-ACK was ever sent, so
    /// there's no real seq/ack state to reply from — just the device's
    /// original SYN to react to).
    private func sendRFC793Reset(key: SessionKey, srcIP: String, srcPort: UInt16,
                                  incomingSeq: UInt32, incomingAck: UInt32 = 0,
                                  incomingHasACK: Bool, consumed: UInt32) {
        let seq: UInt32
        let ack: UInt32
        let flags: UInt8
        if incomingHasACK {
            seq = incomingAck
            ack = 0
            flags = 0x04                 // RST
        } else {
            seq = 0
            ack = incomingSeq &+ consumed
            flags = 0x04 | 0x10          // RST + ACK
        }
        let packet = buildIPv4TCPPacket(
            srcIP: key.dstIP, dstIP: srcIP,
            srcPort: key.dstPort, dstPort: srcPort,
            seq: seq, ack: ack, flags: flags, payload: Data()
        )
        flow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
        onPacket(packet, .inbound, true)
    }

    /// Retransmission/reorder dedup on the device's own sequence numbers,
    /// mirroring `TLSSession.receive` in TLSInterceptor.swift: a segment
    /// whose `seq` doesn't match the expected `clientSeq` is a retransmit or
    /// a gap and is dropped rather than blindly appended (accepting it would
    /// desync our ack from what the device actually sent). Every call still
    /// acks: an in-window segment gets its bytes acked; an out-of-window one
    /// gets a duplicate ack of the unchanged `clientSeq`, telling the device
    /// what to (re)send.
    private func handleDeviceData(session: ActiveSession, key: SessionKey, srcIP: String, srcPort: UInt16,
                                   tcpSeq: UInt32, payload: Data) {
        let expected = session.clientSeq
        let inWindow = tcpSeq == expected
        if inWindow {
            session.clientSeq = session.clientSeq &+ UInt32(truncatingIfNeeded: payload.count)
            session.connection.send(content: payload, completion: .idempotent)
        } else {
            // UInt32 wrapping arithmetic throughout, deliberately not
            // Int32(bitPattern:): a diff that wraps to exactly 0x8000_0000
            // (a 2^31 gap) bit-patterns to Int32.min, and negating that
            // traps — a single malformed/injected segment could crash the
            // whole extension. Diffs below 0x8000_0000 mean tcpSeq is
            // behind expected (a retransmit); at or above means it's ahead
            // (a gap), with the exact boundary an arbitrary but harmless
            // tie-break, same as the old `delta > 0` check made.
            let diff = expected &- tcpSeq
            let isRetransmit = diff != 0 && diff < 0x8000_0000
            let magnitude = isRetransmit ? diff : (UInt32(0) &- diff)
            let label = isRetransmit ? "retransmit, \(magnitude) bytes behind" : "gap, \(magnitude) bytes ahead"
            logger.debug("[\(srcIP, privacy: .public):\(srcPort)→\(key.dstIP, privacy: .public):\(key.dstPort)] DROP (\(label, privacy: .public)) seq=\(tcpSeq) expected=\(expected) len=\(payload.count)")
        }
        sendControlPacket(session: session, key: key, srcIP: srcIP, srcPort: srcPort, flags: 0x10)
    }

    /// A reply to the device's own FIN — previously it got nothing at all,
    /// which is the real cause of the old 60s-idle-sweep-then-hang scan
    /// symptom. `tcpSeq`/`payload` here may be a FIN coalesced with a final
    /// write (Darwin's TCP stack routinely does write-then-close as one
    /// segment), so any payload is delivered first, same as the
    /// TLSInterceptor path handles it, before computing the FIN's own
    /// sequence number (`tcpSeq + payload.count`: the FIN consumes the slot
    /// right after the data).
    private func handleDeviceFIN(session: ActiveSession, key: SessionKey, srcIP: String, srcPort: UInt16,
                                  tcpSeq: UInt32, payload: Data) {
        let finSeq = tcpSeq &+ UInt32(payload.count)
        if !payload.isEmpty {
            handleDeviceData(session: session, key: key, srcIP: srcIP, srcPort: srcPort,
                              tcpSeq: tcpSeq, payload: payload)
        }
        // handleDeviceData only advances clientSeq when the (possibly
        // coalesced) payload was in-window; if it wasn't, clientSeq is
        // still short of finSeq here. Closing anyway would have
        // closeTCPSession's deviceFINSeq bump ack straight past whatever
        // gap caused the drop, silently truncating the stream with no
        // retransmit ever requested. Same check covers a bare out-of-window
        // FIN too (payload empty: finSeq == tcpSeq, so this is just
        // tcpSeq == session.clientSeq).
        guard session.clientSeq == finSeq else {
            if payload.isEmpty {
                // handleDeviceData already sent a duplicate ack above when
                // there was a payload; a bare FIN needs its own.
                sendControlPacket(session: session, key: key, srcIP: srcIP, srcPort: srcPort, flags: 0x10)
            }
            return
        }
        closeTCPSession(session, key: key, srcIP: srcIP, srcPort: srcPort, deviceFINSeq: finSeq)
    }

    /// Single teardown choke point for the plain-relay TCP path, mirroring
    /// `TLSSession.close(deviceFINSeq:)` in TLSInterceptor.swift: reachable
    /// from the device's own FIN/RST, the relay connection's natural EOF,
    /// and the relay connection failing before or after the handshake.
    /// `deviceFINSeq` handles the simultaneous-close case the same way
    /// TLSSession does — our own close (e.g. the real destination finishing
    /// its response) can land at essentially the same moment the device
    /// sends its own FIN, and that FIN's sequence number still needs to be
    /// acked even though this call's own final packet is unconditional.
    private func closeTCPSession(_ session: ActiveSession, key: SessionKey, srcIP: String, srcPort: UInt16,
                                  deviceFINSeq: UInt32? = nil, sendReset: Bool = false, notifyDevice: Bool = true) {
        guard sessions[key] === session, !session.torndown else { return }
        session.torndown = true
        endSignpostIfNoReply(session)
        session.connection.cancel()
        // Left in `sessions` (marked torndown) instead of removed
        // immediately, and lastActivity refreshed so the existing 60s idle
        // sweep reaps it: the device's own closing FIN/ACK for this same
        // exchange (a normal four-way close, or the simultaneous-close
        // case) routinely arrives right after our final packet below.
        // Removing the key now made that trailing packet look like an
        // unknown session to forwardTCP, which replied with an RFC 9293
        // reset — confirmed on-device: every clean plain-relay close in
        // pcap testing ended with a spurious extra RST/RST pair after an
        // otherwise normal FIN/FIN/ACK exchange, before this fix.
        session.lastActivity = Date()

        guard notifyDevice else { return }

        guard session.handshakeCompleted else {
            // No SYN-ACK was ever sent (the relay's own connection never
            // reached .ready): the device is still effectively SYN_SENT, so
            // reply with the RFC 9293 reset-generation form for a segment
            // with no ACK flag (seq=0, ack=their SYN's seq+1) instead of
            // leaving it to retransmit its SYN until it gives up on its own.
            sendRFC793Reset(key: key, srcIP: srcIP, srcPort: srcPort,
                             incomingSeq: session.clientISN, incomingHasACK: false, consumed: 1)
            return
        }

        if let deviceFINSeq {
            let bumped = max(session.clientSeq, deviceFINSeq &+ 1)
            if bumped != session.clientSeq {
                session.clientSeq = bumped
                sendControlPacket(session: session, key: key, srcIP: srcIP, srcPort: srcPort, flags: 0x10)
            }
        }
        sendControlPacket(session: session, key: key, srcIP: srcIP, srcPort: srcPort,
                           flags: sendReset ? 0x04 : 0x11)
        if !sendReset {
            // Our FIN just consumed one sequence number, same as any other
            // TCP segment; the torndown-session branch in forwardTCP needs
            // this to already be advanced when it acks a device FIN/data
            // segment that arrives after this call returns.
            session.serverSeq &+= 1
            session.closedGracefully = true
        }
    }

    private func receiveTCP(conn: NWConnection, key: SessionKey,
                            srcIP: String, srcPort: UInt16, session: ActiveSession) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65535) { [weak self] content, _, isComplete, error in
            // !session.torndown matters now that closeTCPSession no longer
            // removes the session from `sessions` immediately (both run on
            // the same serial queue, so a receive completion already
            // dispatched right as teardown ran would otherwise still pass
            // this guard): without it, a data segment could be sent to the
            // device after our FIN, at the FIN's own sequence number, which
            // a real TCP stack answers with RST.
            guard let self, self.running, self.sessions[key] === session, !session.torndown else { return }
            if let payload = content, !payload.isEmpty, session.handshakeCompleted {
                self.writeToDevice(payload, session: session, key: key, srcIP: srcIP, srcPort: srcPort)
            }
            if !isComplete && error == nil {
                self.receiveTCP(conn: conn, key: key, srcIP: srcIP, srcPort: srcPort, session: session)
            } else {
                // The real destination closed (or the connection errored).
                // Tell the device via a synthetic FIN (graceful) or RST
                // (error) instead of just dropping the session and leaving
                // the device to time out on its own — same reasoning as
                // TLSSession.close() being reached from every termination
                // path, not just the device-initiated one.
                self.closeTCPSession(session, key: key, srcIP: srcIP, srcPort: srcPort, sendReset: error != nil)
            }
        }
    }

    /// Splits a real-destination reply into MSS-sized segments instead of
    /// one packet holding the whole payload, same fix and same reasoning as
    /// `TLSSession.writeToDevice` in TLSInterceptor.swift (2026-09-26): a
    /// reply easily runs past 1460 bytes, and a single oversized synthetic
    /// segment silently violates the MSS advertised in our own SYN-ACK and
    /// the tunnel's MTU, which the device's kernel just never acks.
    private func writeToDevice(_ data: Data, session: ActiveSession, key: SessionKey, srcIP: String, srcPort: UInt16) {
        var offset = data.startIndex
        while offset < data.endIndex {
            let end = data.index(offset, offsetBy: Self.advertisedMSS, limitedBy: data.endIndex) ?? data.endIndex
            let chunk = data[offset..<end]
            let packet = buildIPv4TCPPacket(
                srcIP: key.dstIP, dstIP: srcIP,
                srcPort: key.dstPort, dstPort: srcPort,
                seq: session.serverSeq, ack: session.clientSeq,
                flags: 0x18, payload: Data(chunk)
            )
            session.serverSeq &+= UInt32(truncatingIfNeeded: chunk.count)
            flow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
            onPacket(packet, .inbound, true)
            offset = end
        }
        session.lastActivity = Date()
        if !session.firstReplyRecorded, let state = session.relaySignpostState {
            session.firstReplyRecorded = true
            signposter.endInterval("relayFlow", state)
        }
    }

    // MARK: - Packet construction

    // Both builders below patch in real IPv4 header + UDP/TCP checksums,
    // previously left as 0x0000. TLSInterceptor.swift's synthetic packets had
    // the same defect and fixing it there is what got a real device to accept
    // a synthetic SYN-ACK at all; this plain relay path builds packets the
    // same way (raw bytes into flow.writePackets) and was fixed alongside it.
    // UDP's own checksum field is spec-allowed to be zero ("no checksum
    // computed", RFC 768) and this relay evidently still works for UDP
    // without it (DNS through it has been observed working), but the IPv4
    // header checksum has no such allowance, and a real checksum is never
    // wrong to send.
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

    /// `ack`/`flags`/`options` generalize this beyond the original
    /// data-only, ack-hardcoded-to-0 builder (todo.md item 1): the plain
    /// relay path now needs the SYN-ACK, pure ACKs, FIN, and RST shapes too,
    /// same as `TLSSession.buildTCPPacket` in TLSInterceptor.swift.
    /// `options` is padded to a 4-byte boundary and the data-offset nibble
    /// is derived from the resulting header length, so the offset byte is
    /// 0x50 only for the no-options case, not hardcoded.
    private func buildIPv4TCPPacket(srcIP: String, dstIP: String,
                                     srcPort: UInt16, dstPort: UInt16,
                                     seq: UInt32, ack: UInt32 = 0,
                                     flags: UInt8 = 0x18,
                                     payload: Data = Data(),
                                     options: Data = Data()) -> Data {
        var opts = options
        while opts.count % 4 != 0 { opts.append(0x00) }
        precondition(opts.count <= 40, "TCP options exceed the 40-byte maximum")
        let tcpHeaderLen = 20 + opts.count                     // multiple of 4, 20...60
        let dataOffsetByte = UInt8(tcpHeaderLen / 4) << 4      // upper nibble = header words

        let tcpLen   = UInt16(tcpHeaderLen + payload.count)
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
        p.appendBE32(seq)
        p.appendBE32(ack)
        p.append(dataOffsetByte)
        p.append(flags)
        p.appendBE16(65535)                 // window size
        p.appendBE16(0x0000)               // TCP checksum, patched below
        p.appendBE16(0x0000)               // urgent pointer
        p.append(opts)
        p.append(payload)

        var bytes = [UInt8](p)
        let ipChecksum = PacketChecksum.internetChecksum(bytes[0..<20])
        bytes[10] = UInt8(ipChecksum >> 8); bytes[11] = UInt8(ipChecksum & 0xFF)

        // TCP checksum covers the pseudo-header plus the whole segment
        // (header, options, payload). The checksum field itself is at a
        // fixed offset (IP 20 + TCP 16 = 36) regardless of options.
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
        } else if tlsInterceptor == nil && TLSInterceptor.hasCompleteCAIdentity() {
            tlsInterceptor = TLSInterceptor(onPacket: onPacket)
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
    /// connection failure, or the peer closing first): the counterpart to
    /// the normal close in `receiveUDP`/`receiveTCP`. Without this, a
    /// never-answered flow (exactly the case this instrumentation exists to
    /// catch, e.g. a scan probe that times out) would leave its interval
    /// open forever instead of recording "no reply within N seconds".
    private func endSignpostIfNoReply(_ session: ActiveSession) {
        guard !session.firstReplyRecorded, let state = session.relaySignpostState else { return }
        session.firstReplyRecorded = true
        signposter.endInterval("relayFlow", state, "no reply")
    }

    /// Removes `key`'s entry only if it still points at `session`: a delayed
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

    // TCP handshake/state tracking for the plain-relay path (todo.md item 1).
    // `clientISN` is the device's original SYN sequence number, kept so a
    // pre-handshake reset (the relay's own connection never reached .ready)
    // can still ack it correctly. `serverSeq`/`clientSeq` are only
    // meaningful once `handshakeCompleted` is true, which is set only when
    // our SYN-ACK is actually sent — deliberately deferred until the
    // relay's own NWConnection reaches .ready, since sending it earlier
    // would tell the device every filtered/dropped destination port is open.
    var clientISN: UInt32 = 0
    var clientSeq: UInt32 = 0
    var serverSeq: UInt32 = 100_000
    var synAckSeq: UInt32?
    var handshakeCompleted = false
    // Guards closeTCPSession against sending its teardown packet twice, e.g.
    // once for the device's own FIN and again for the relay connection's own
    // natural EOF arriving right after.
    var torndown = false
    // Set only when closeTCPSession's final packet was a FIN, not an RST.
    // forwardTCP's torndown-session branch uses this to decide whether a
    // packet arriving after teardown still needs a real ack (the device's
    // own closing FIN/data crossing ours) or can be silently absorbed (an
    // RST already gave the device a definitive, ack-free answer).
    var closedGracefully = false

    /// Signpost interval covering "session opened" → "first reply relayed
    /// back to the device". Ended once, on the first reply only: a
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
