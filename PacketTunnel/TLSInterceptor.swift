// PacketTunnel/TLSInterceptor.swift
import Foundation
import Security
import Network
import NetworkExtension

// MARK: - SNI Parser

func parseSNI(from buffer: Data) -> String? {
    let bytes = [UInt8](buffer)
    guard bytes.count > 5, bytes[0] == 0x16 else { return nil }
    let recLen = Int(bytes[3]) << 8 | Int(bytes[4])
    guard bytes.count >= 5 + recLen else { return nil }
    guard bytes[5] == 0x01 else { return nil }
    var i = 5 + 4
    guard i + 34 < bytes.count else { return nil }
    i += 2 + 32
    let sessionLen = Int(bytes[i]); i += 1 + sessionLen
    guard i + 2 <= bytes.count else { return nil }
    let cipherLen = Int(bytes[i]) << 8 | Int(bytes[i+1]); i += 2 + cipherLen
    guard i + 1 <= bytes.count else { return nil }
    let compLen = Int(bytes[i]); i += 1 + compLen
    guard i + 2 <= bytes.count else { return nil }
    let extTotal = Int(bytes[i]) << 8 | Int(bytes[i+1]); i += 2
    let extEnd = i + extTotal
    while i + 4 <= extEnd && i + 4 <= bytes.count {
        let extType = Int(bytes[i]) << 8 | Int(bytes[i+1])
        let extLen  = Int(bytes[i+2]) << 8 | Int(bytes[i+3])
        i += 4
        if extType == 0x0000 {
            guard i + 5 <= bytes.count else { return nil }
            let nameLen = Int(bytes[i+3]) << 8 | Int(bytes[i+4])
            guard i + 5 + nameLen <= bytes.count else { return nil }
            return String(bytes: Array(bytes[(i+5)..<(i+5+nameLen)]), encoding: .utf8)
        }
        i += extLen
    }
    return nil
}

// MARK: - LeafCertCache

final class LeafCertCache {
    private static let maxSize = 200
    private var cache: [String: SecIdentity] = [:]
    private var insertionOrder: [String] = []
    private let lock = NSLock()

    func identity(for domain: String) throws -> SecIdentity {
        lock.lock(); defer { lock.unlock() }
        if let id = cache[domain] { return id }
        let id = try makeIdentity(domain: domain)
        cache[domain] = id
        insertionOrder.append(domain)
        if insertionOrder.count > Self.maxSize {
            let evicted = insertionOrder.removeFirst()
            cache.removeValue(forKey: evicted)
            KeychainStore.deleteAllLeafItems(domains: [evicted])
        }
        return id
    }

    private func makeIdentity(domain: String) throws -> SecIdentity {
        guard let caKey = KeychainStore.loadCAKey() else {
            throw TLSInterceptorError.caKeyMissing
        }
        let tag = Data("mdns.leaf.\(domain)".utf8)
        SecItemDelete([
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessGroup as String: KeychainStore.accessGroup
        ] as CFDictionary)
        let keyAttrs: [String: Any] = [
            kSecAttrKeyType as String:        kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String:  256,
            kSecAttrIsPermanent as String:    true,
            kSecAttrAccessGroup as String:    KeychainStore.accessGroup,
            kSecAttrApplicationTag as String: tag
        ]
        var cfErr: Unmanaged<CFError>?
        guard let leafPrivKey = SecKeyCreateRandomKey(keyAttrs as CFDictionary, &cfErr) else {
            throw cfErr!.takeRetainedValue() as Error
        }
        guard let leafPubKey = SecKeyCopyPublicKey(leafPrivKey) else {
            throw TLSInterceptorError.cannotExtractPublicKey
        }
        let certDER = try X509CertBuilder.buildLeafCert(
            domain: domain, leafPublicKey: leafPubKey, caPrivateKey: caKey
        )
        guard let cert = SecCertificateCreateWithData(nil, certDER as CFData) else {
            throw TLSInterceptorError.certCreationFailed
        }
        try KeychainStore.saveLeafCert(cert, domain: domain)
        guard let id = KeychainStore.loadLeafIdentity(domain: domain) else {
            throw TLSInterceptorError.identityLookupFailed
        }
        return id
    }

    func purge() {
        lock.lock()
        let domains = Array(cache.keys)
        cache.removeAll()
        insertionOrder.removeAll()
        lock.unlock()
        KeychainStore.deleteAllLeafItems(domains: domains)
    }
}

// MARK: - Error types

enum TLSInterceptorError: Error, LocalizedError {
    case caKeyMissing
    case cannotExtractPublicKey
    case certCreationFailed
    case identityLookupFailed
    case handshakeFailed(OSStatus)
    case upstreamFailed
    var errorDescription: String? {
        switch self {
        case .caKeyMissing:            return "CA private key not found in keychain"
        case .cannotExtractPublicKey:  return "Cannot extract public key from leaf private key"
        case .certCreationFailed:      return "Failed to create leaf certificate"
        case .identityLookupFailed:    return "Cannot find SecIdentity for leaf cert+key pair"
        case .handshakeFailed(let s):  return "TLS handshake failed (OSStatus \(s))"
        case .upstreamFailed:          return "Upstream TLS connection failed"
        }
    }
}

// MARK: - TLSSession

final class TLSSession {
    let key: SessionKey
    let srcIP: String
    let dstIP: String
    let dstPort: UInt16
    let flow: NEPacketTunnelFlow
    let certCache: LeafCertCache

    private var serverSeq: UInt32 = 100_000
    private var clientSeq: UInt32 = 0

    private var inboundBuffer = Data()
    private let condition = NSCondition()
    private var sessionClosed = false

    // Network.framework + POSIX bridge
    private var proxyFD: Int32 = -1
    private var tlsListener: NWListener?
    private var upstream: NWConnection?

    var lastActivity = Date()

    init(key: SessionKey, srcIP: String, dstIP: String, dstPort: UInt16,
         clientISN: UInt32, flow: NEPacketTunnelFlow, certCache: LeafCertCache) {
        self.key       = key
        self.srcIP     = srcIP
        self.dstIP     = dstIP
        self.dstPort   = dstPort
        self.clientSeq = clientISN &+ 1
        self.flow      = flow
        self.certCache = certCache
    }

    func sendSYNACK() {
        let packet = buildTCPPacket(
            srcIP: dstIP, dstIP: srcIP,
            srcPort: dstPort, dstPort: key.srcPort,
            seq: serverSeq, ack: clientSeq,
            flags: 0x12, payload: Data()
        )
        serverSeq &+= 1
        flow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
    }

    func receive(_ data: Data) {
        condition.lock()
        inboundBuffer.append(data)
        lastActivity = Date()
        condition.signal()
        condition.unlock()
    }

    func close() {
        condition.lock()
        let alreadyClosed = sessionClosed
        sessionClosed = true
        condition.signal()
        condition.unlock()
        guard !alreadyClosed else { return }

        let fd = proxyFD
        if fd != -1 {
            shutdown(fd, SHUT_RDWR)
            Darwin.close(fd)
        }
        tlsListener?.cancel()
        upstream?.cancel()
    }

    func writeToDevice(_ data: Data) {
        let packet = buildTCPPacket(
            srcIP: dstIP, dstIP: srcIP,
            srcPort: dstPort, dstPort: key.srcPort,
            seq: serverSeq, ack: clientSeq,
            flags: 0x18, payload: data
        )
        serverSeq = serverSeq &+ UInt32(data.count)
        flow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
    }

    func start(onDecryptedRequest: @escaping (Data, String) -> Void) {
        Thread.detachNewThread { self.runSession(onDecryptedRequest: onDecryptedRequest) }
    }

    // MARK: - Session runner

    private func runSession(onDecryptedRequest: @escaping (Data, String) -> Void) {
        // Wait for ClientHello bytes to parse SNI
        condition.lock()
        let deadline = Date().addingTimeInterval(10)
        while inboundBuffer.count < 6 && !sessionClosed {
            if !condition.wait(until: deadline) { break }
        }
        let snapshot = inboundBuffer          // keep bytes in buffer for deviceToProxy
        condition.unlock()

        let sni = parseSNI(from: snapshot) ?? dstIP

        if SharedSettings.tlsBypassList.contains(where: { sni == $0 || sni.hasSuffix(".\($0)") }) {
            close(); return
        }

        guard let identity = try? certCache.identity(for: sni) else {
            SharedSettings.incrementDropCount()
            close(); return
        }

        // Build NWListener with the per-domain leaf identity
        let tlsOpts = NWProtocolTLS.Options()
        guard let secIdent = sec_identity_create(identity) else {
            SharedSettings.incrementDropCount()
            close(); return
        }
        sec_protocol_options_set_local_identity(tlsOpts.securityProtocolOptions, secIdent)
        sec_protocol_options_set_peer_authentication_required(
            tlsOpts.securityProtocolOptions, false)

        let listenerParams = NWParameters(tls: tlsOpts, tcp: NWProtocolTCP.Options())

        let lst: NWListener
        do { lst = try NWListener(using: listenerParams) } catch {
            SharedSettings.incrementDropCount()
            close(); return
        }
        tlsListener = lst

        // Wait for listener to be ready and capture the ephemeral port
        let listenerSem = DispatchSemaphore(value: 0)
        var listenerPort: UInt16 = 0
        lst.stateUpdateHandler = { state in
            switch state {
            case .ready:
                listenerPort = lst.port?.rawValue ?? 0
                listenerSem.signal()
            case .failed, .cancelled:
                listenerSem.signal()
            default: break
            }
        }

        // Capture the first accepted NWConnection (our POSIX-bridge connection)
        let acceptSem = DispatchSemaphore(value: 0)
        var acceptedConn: NWConnection?
        lst.newConnectionHandler = { conn in
            acceptedConn = conn
            lst.cancel()       // one connection is all we need
            acceptSem.signal()
        }

        lst.start(queue: .global())
        listenerSem.wait()

        guard listenerPort > 0, !sessionClosed else {
            SharedSettings.incrementDropCount()
            close(); return
        }

        // POSIX socket - connects to NWListener on loopback, bridging raw bytes to TLS
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            SharedSettings.incrementDropCount()
            close(); return
        }

        var addr = sockaddr_in()
        addr.sin_len    = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port   = listenerPort.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let connectOK = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        } == 0

        guard connectOK else {
            Darwin.close(fd)
            SharedSettings.incrementDropCount()
            close(); return
        }
        proxyFD = fd

        // Wait for NWListener to accept our POSIX connection
        acceptSem.wait()
        guard let tlsConn = acceptedConn, !sessionClosed else {
            SharedSettings.incrementDropCount()
            close(); return
        }

        // Connect to the real upstream TLS server
        let upstreamConn = NWConnection(
            host: NWEndpoint.Host(dstIP),
            port: NWEndpoint.Port(rawValue: dstPort)!,
            using: .tls
        )
        upstream = upstreamConn
        let upstreamSem = DispatchSemaphore(value: 0)
        upstreamConn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready, .failed: upstreamSem.signal()
            default: break
            }
        }
        upstreamConn.start(queue: .global())
        upstreamSem.wait()

        guard case .ready = upstreamConn.state else {
            SharedSettings.incrementDropCount()
            close(); return
        }

        // Start the NWListener-accepted connection (triggers TLS handshake with POSIX client)
        tlsConn.start(queue: .global())

        // Thread A: drain inboundBuffer → POSIX fd (device bytes → NWListener TLS input)
        Thread.detachNewThread { self.deviceToProxy(fd: fd) }

        // Thread B: POSIX fd recv → IP packets to device (NWListener TLS output → device)
        Thread.detachNewThread { self.proxyToDevice(fd: fd) }

        // Async receive chains (independent directions, both started before returning)
        receiveFromTLS(tlsConn: tlsConn, sni: sni, upstream: upstreamConn,
                       onDecryptedRequest: onDecryptedRequest)
        receiveFromUpstream(upstream: upstreamConn, tlsConn: tlsConn)
    }

    // MARK: - Data paths

    // Device bytes → POSIX fd (feeds the NWListener TLS state machine)
    private func deviceToProxy(fd: Int32) {
        while !sessionClosed {
            condition.lock()
            let deadline = Date().addingTimeInterval(30)
            while inboundBuffer.isEmpty && !sessionClosed {
                if !condition.wait(until: deadline) { break }
            }
            let chunk = inboundBuffer
            inboundBuffer.removeAll(keepingCapacity: true)
            condition.unlock()

            guard !chunk.isEmpty, !sessionClosed else { continue }
            chunk.withUnsafeBytes { ptr in
                guard let base = ptr.baseAddress else { return }
                var offset = 0
                while offset < chunk.count && !sessionClosed {
                    let n = Darwin.send(fd, base.advanced(by: offset),
                                        chunk.count - offset, 0)
                    if n <= 0 { return }
                    offset += n
                }
            }
        }
    }

    // POSIX fd → IP+TCP packets to device (NWListener TLS-encrypted output → device)
    private func proxyToDevice(fd: Int32) {
        var buf = [UInt8](repeating: 0, count: 16384)
        while !sessionClosed {
            let n = Darwin.recv(fd, &buf, buf.count, 0)
            if n <= 0 { break }
            writeToDevice(Data(buf.prefix(n)))
        }
    }

    // NWListener plaintext → callback + upstream send
    private func receiveFromTLS(tlsConn: NWConnection, sni: String,
                                upstream: NWConnection,
                                onDecryptedRequest: @escaping (Data, String) -> Void) {
        tlsConn.receive(minimumIncompleteLength: 1, maximumLength: 65535) { [weak self] data, _, isDone, _ in
            guard let self else { return }
            if let data, !data.isEmpty {
                onDecryptedRequest(data, sni)
                upstream.send(content: data, completion: .idempotent)
            }
            if !isDone && !self.sessionClosed {
                self.receiveFromTLS(tlsConn: tlsConn, sni: sni, upstream: upstream,
                                    onDecryptedRequest: onDecryptedRequest)
            } else {
                self.close()
            }
        }
    }

    // Upstream response → NWListener (re-encrypts and sends through POSIX fd to device)
    private func receiveFromUpstream(upstream: NWConnection, tlsConn: NWConnection) {
        upstream.receive(minimumIncompleteLength: 1, maximumLength: 65535) { [weak self] data, _, isDone, _ in
            guard let self else { return }
            if let data, !data.isEmpty {
                tlsConn.send(content: data, completion: .idempotent)
            }
            if !isDone && !self.sessionClosed {
                self.receiveFromUpstream(upstream: upstream, tlsConn: tlsConn)
            } else {
                self.close()
            }
        }
    }

    // MARK: - Packet builder

    private func buildTCPPacket(srcIP: String, dstIP: String,
                                 srcPort: UInt16, dstPort: UInt16,
                                 seq: UInt32, ack: UInt32,
                                 flags: UInt8, payload: Data) -> Data {
        let tcpLen   = UInt16(20 + payload.count)
        let totalLen = UInt16(20 + tcpLen)
        var p = Data(capacity: Int(totalLen))
        p.append(0x45); p.append(0x00)
        p.appendBE16(totalLen)
        p.appendBE16(0x0000)
        p.appendBE16(0x4000)
        p.append(64); p.append(6); p.appendBE16(0x0000)
        p.append(ipOctets: srcIP)
        p.append(ipOctets: dstIP)
        p.appendBE16(srcPort); p.appendBE16(dstPort)
        p.appendBE32(seq); p.appendBE32(ack)
        p.append(0x50)
        p.append(flags)
        p.appendBE16(65535); p.appendBE16(0x0000); p.appendBE16(0x0000)
        p.append(payload)
        return p
    }
}

// MARK: - TLSInterceptor coordinator

final class TLSInterceptor {
    private var sessions: [SessionKey: TLSSession] = [:]
    private let lock = NSLock()
    let certCache = LeafCertCache()

    func openSession(key: SessionKey, srcIP: String, dstIP: String,
                     clientISN: UInt32, flow: NEPacketTunnelFlow,
                     onDecryptedRequest: @escaping (Data, String) -> Void) {
        let session = TLSSession(
            key: key, srcIP: srcIP, dstIP: dstIP, dstPort: key.dstPort,
            clientISN: clientISN, flow: flow, certCache: certCache
        )
        lock.lock(); sessions[key] = session; lock.unlock()
        session.sendSYNACK()
        session.start(onDecryptedRequest: onDecryptedRequest)
    }

    func hasSession(for key: SessionKey) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return sessions[key] != nil
    }

    func deliver(_ data: Data, for key: SessionKey) {
        lock.lock(); let s = sessions[key]; lock.unlock()
        s?.receive(data)
    }

    func closeSession(for key: SessionKey) {
        lock.lock(); let s = sessions.removeValue(forKey: key); lock.unlock()
        s?.close()
    }

    func stop() {
        lock.lock(); let all = Array(sessions.values); sessions.removeAll(); lock.unlock()
        all.forEach { $0.close() }
        certCache.purge()
    }
}
