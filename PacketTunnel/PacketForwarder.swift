// PacketTunnel/PacketForwarder.swift
import Foundation
import NetworkExtension
import Network

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

    init(flow: NEPacketTunnelFlow,
         onDecryptedHTTPS: ((Data, String) -> Void)? = nil,
         onPacket: @escaping PacketHandler) {
        self.flow = flow
        self.onDecryptedHTTPS = onDecryptedHTTPS
        self.onPacket = onPacket
    }

    func start() {
        running = true
        if SharedSettings.tlsInspectionEnabled && KeychainStore.loadCAKey() != nil {
            tlsInterceptor = TLSInterceptor()
        } else if SharedSettings.tlsInspectionEnabled {
            SharedSettings.tlsInterceptorLastError = "TLS inspection is off - CA key not found in keychain"
        }
        scheduleCleanup()
    }

    func stop() {
        running = false
        cleanupTimer?.cancel()
        tlsInterceptor?.stop()
        tlsInterceptor = nil
        queue.sync {
            sessions.values.forEach { $0.connection.cancel() }
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
        sessions[key] = session

        conn.stateUpdateHandler = { [weak self] state in
            if case .failed = state { self?.queue.async { self?.sessions.removeValue(forKey: key) } }
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
            self.queue.async { self.sessions[key]?.lastActivity = Date() }
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
                if isFIN || isRST {
                    interceptor.closeSession(for: key)
                } else if !payload.isEmpty {
                    interceptor.deliver(payload, for: key)
                }
                return
            }

            if isFIN || isRST {
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
            return false
        }
        // Extract client ISN from the SYN packet (sequence number field in TCP header)
        let ihl = Int(bytes[0] & 0x0F) * 4
        let clientISN = UInt32(bytes[ihl+4]) << 24 | UInt32(bytes[ihl+5]) << 16
                      | UInt32(bytes[ihl+6]) << 8  | UInt32(bytes[ihl+7])
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
        sessions[key] = session

        conn.stateUpdateHandler = { [weak self] state in
            switch state {
            case .failed, .cancelled:
                self?.queue.async { self?.sessions.removeValue(forKey: key) }
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
                self.queue.async { session.lastActivity = Date() }
            }
            if !isComplete && error == nil {
                self.receiveTCP(conn: conn, key: key, srcIP: srcIP, srcPort: srcPort, session: session)
            } else {
                self.queue.async { self.sessions.removeValue(forKey: key) }
            }
        }
    }

    // MARK: - Packet construction

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
        p.appendBE16(0x0000)               // checksum (0 = not computed)
        p.append(ipOctets: srcIP)
        p.append(ipOctets: dstIP)
        // UDP header
        p.appendBE16(srcPort)
        p.appendBE16(dstPort)
        p.appendBE16(udpLen)
        p.appendBE16(0x0000)               // checksum
        p.append(payload)
        return p
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
        p.appendBE16(0x0000)
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
        p.appendBE16(0x0000)               // checksum
        p.appendBE16(0x0000)               // urgent pointer
        p.append(payload)
        return p
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
        t.setEventHandler { [weak self] in self?.removeIdleSessions() }
        t.resume()
        cleanupTimer = t
    }

    private func removeIdleSessions() {
        let cutoff = Date().addingTimeInterval(-60)
        sessions = sessions.filter { _, session in
            if session.lastActivity < cutoff { session.connection.cancel(); return false }
            return true
        }
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
