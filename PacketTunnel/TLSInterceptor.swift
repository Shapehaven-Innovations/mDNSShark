// PacketTunnel/TLSInterceptor.swift
import Foundation
import Security
import Network
import NetworkExtension
import os

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

    // `serverSeq` is the next sequence number we will send; `clientSeq` is
    // the next sequence number we expect from the device (i.e. our ack
    // number). Both are touched from more than one thread — `receive(_:)`
    // runs on PacketForwarder's queue and `writeToDevice(_:)` on the
    // proxyToDevice thread — so every read/modify of them, and the
    // writePackets that consumes the pair, happens under `seqLock`. Holding
    // the lock across the write also keeps our synthetic packets leaving in
    // sequence-number order.
    private var serverSeq: UInt32 = 100_000
    private var clientSeq: UInt32 = 0
    private let seqLock = NSLock()

    private var inboundBuffer = Data()
    private let condition = NSCondition()
    private var sessionClosed = false

    // Diagnostic for todo.md item 1's checksum spike — the decisive
    // question is whether the device's kernel ever ACKs sendSYNACK()'s
    // packet at all. Logged once, not every packet: `receive(_:)` fires on
    // every inbound chunk, and this session lives across an entire TLS
    // connection's worth of them.
    private let logger = Logger(subsystem: "com.mDNSShark.PacketTunnel", category: "TLSInterceptor")
    private var loggedFirstReceive = false

    // Diagnostic scaffolding for the on-device HTTPS-hang investigation
    // (todo.md item 1). `stage` names the last step runSession reached so
    // close() can report *where* a session died — every guard in
    // runSession used to bail via `incrementDropCount(); close(); return`
    // with no indication of which one fired. `receiveCount` gates the
    // per-chunk log to the first few inbound chunks (enough to see a
    // ClientHello and any retransmission of it); `wroteFirstToDevice`
    // gates the first-reply log. `t0`/`elapsedMs` timestamp each line so
    // a multi-minute stall can be pinned to one wait.
    //
    // `stage` specifically is written from more than one thread once
    // tlsConn.start(queue: .global()) is called below (its state handler and
    // receiveFromTLS's callback both run there, concurrently with each
    // other and with runSession's own thread) — lock-protected so a
    // diagnostic meant to answer "which stage did we die at" doesn't itself
    // race.
    private var _stage = "opened"
    private let stageLock = NSLock()
    private var stage: String {
        get { stageLock.lock(); defer { stageLock.unlock() }; return _stage }
        set { stageLock.lock(); defer { stageLock.unlock() }; _stage = newValue }
    }
    private var receiveCount = 0
    private var wroteFirstToDevice = false
    private let t0 = Date()
    private var elapsedMs: Int { Int(Date().timeIntervalSince(t0) * 1000) }
    private lazy var tag = "\(srcIP):\(key.srcPort)→\(dstIP):\(dstPort)"

    // Network.framework + POSIX bridge
    private var proxyFD: Int32 = -1
    private var tlsListener: NWListener?
    private var upstream: NWConnection?

    var lastActivity = Date()

    // Set by TLSInterceptor.openSession right after construction. close() was
    // previously only ever removed from TLSInterceptor.sessions by the
    // device-FIN/RST path (closeSession(for:)) — a session that closes itself
    // (e.g. one of the bounded listener/accept/upstream timeouts) left a dead
    // entry keyed by the same 4-tuple, so a device SYN retransmit on that key
    // found hasSession(for:) still true and PacketForwarder just logged it
    // instead of ever retrying the handshake — the flow stayed wedged until
    // the device gave up, reproducing the exact hang this file's diagnostics
    // exist to catch.
    var onClosed: (() -> Void)?

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

    // MSS option advertised in our SYN-ACK: kind=2, len=4, value=1460 (0x05B4)
    // big-endian. Without it the device's kernel falls back to
    // tcp_mssdflt (512), which the pcap showed as a 1512-byte ClientHello
    // arriving in three 512-byte segments. 1460 is the standard Ethernet
    // value; the tunnel MTU is at least that, and the bytes never touch a
    // real wire anyway — they go straight into inboundBuffer.
    private static let mssOption: Data = Data([0x02, 0x04, 0x05, 0xB4])

    // The ISN used for the SYN-ACK, fixed on the first call. A retransmitted
    // SYN-ACK (PacketForwarder.resendSYNACK, when the device retries its SYN
    // because the first one was rejected) must reuse this exact value —
    // sending a different seq on retry is itself a protocol violation the
    // device's kernel would reject, not something a retry should fix.
    private var synAckSeq: UInt32?

    func sendSYNACK() {
        seqLock.lock(); defer { seqLock.unlock() }
        let seq: UInt32
        if let synAckSeq {
            seq = synAckSeq
        } else {
            seq = serverSeq
            synAckSeq = serverSeq
            serverSeq &+= 1     // SYN consumes one sequence number
        }
        let packet = buildTCPPacket(
            srcIP: dstIP, dstIP: srcIP,
            srcPort: dstPort, dstPort: key.srcPort,
            seq: seq, ack: clientSeq,
            flags: 0x12, payload: Data(),
            options: Self.mssOption
        )
        logger.debug("sendSYNACK to \(self.srcIP, privacy: .public):\(self.key.srcPort) for \(self.dstIP, privacy: .public):\(self.dstPort) seq=\(seq) ack=\(self.clientSeq) mss=1460")
        flow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
    }

    /// `seq` is the TCP sequence number PacketForwarder read from the
    /// device's packet header. A segment whose `seq` doesn't match
    /// `clientSeq` (a retransmit, or reordering) is dropped rather than
    /// blindly appended: accepting it would advance `clientSeq` past bytes
    /// the device never actually sent, making our next ack invalid on the
    /// device's side — its kernel would treat that as unacceptable (RFC
    /// 9293 §3.10.7.4) and silently drop everything we send afterward,
    /// including the ServerHello flight, wedging the connection instead of
    /// just delaying it. Every call still acks: an in-window segment gets
    /// its bytes acked, an out-of-window one gets a duplicate ack of the
    /// unchanged `clientSeq`, telling the device what to (re)send.
    func receive(_ data: Data, seq: UInt32) {
        guard !data.isEmpty else { return }

        seqLock.lock()
        let expected = clientSeq
        let inWindow = seq == expected
        if inWindow {
            clientSeq = clientSeq &+ UInt32(truncatingIfNeeded: data.count)
        }
        let ackPacket = buildTCPPacket(
            srcIP: dstIP, dstIP: srcIP,
            srcPort: dstPort, dstPort: key.srcPort,
            seq: serverSeq, ack: clientSeq,
            flags: 0x10, payload: Data()
        )
        if receiveCount < 6 || !inWindow {
            // Distinguish the two DROP cases: seq behind expected is a
            // retransmit (the device didn't see our ack); seq ahead of
            // expected is a gap on OUR synthetic path (we lost a segment
            // somewhere before this call, e.g. a race in PacketForwarder's
            // queue.async). They point at different places to look.
            let label: String
            if inWindow {
                label = "ACK"
            } else {
                let delta = Int32(bitPattern: expected &- seq)
                label = delta > 0 ? "DROP (retransmit, \(delta) bytes behind)" : "DROP (gap, \(-delta) bytes ahead)"
            }
            logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms \(label, privacy: .public) seq=\(seq) expected=\(expected) len=\(data.count) → ack=\(self.clientSeq)")
        }
        flow.writePackets([ackPacket], withProtocols: [NSNumber(value: AF_INET)])
        seqLock.unlock()

        guard inWindow else { return }

        condition.lock()
        inboundBuffer.append(data)
        let buffered = inboundBuffer.count
        lastActivity = Date()
        condition.signal()
        condition.unlock()

        // First real bytes back from the device is the proof the SYN-ACK
        // was accepted and the kernel completed its handshake — if the
        // checksum fix didn't work, this never fires for this session.
        if !loggedFirstReceive {
            loggedFirstReceive = true
            logger.debug("first device bytes received for \(self.srcIP, privacy: .public):\(self.key.srcPort) → \(self.dstIP, privacy: .public):\(self.dstPort) (\(data.count) bytes) — handshake completed")
        }
        receiveCount += 1
        if receiveCount <= 6 {
            let head = data.prefix(6).map { String(format: "%02x", $0) }.joined(separator: " ")
            logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms device chunk #\(self.receiveCount): \(data.count) bytes head=\(head, privacy: .public) buffered=\(buffered) stage=\(self.stage, privacy: .public)")
        }
    }

    // Records *why* a session was dropped, not just that one was — the
    // Settings screen already shows a running drop count
    // (SharedSettings.tlsInterceptorDropCount) with no reason attached, and
    // on-device Console access has repeatedly been unreliable for reading
    // the per-guard debug log lines below. This makes the last failure
    // visible from the app itself.
    private func dropSession(_ reason: String) {
        SharedSettings.tlsInterceptorLastError = reason
        SharedSettings.incrementDropCount()
    }

    func close() {
        condition.lock()
        let alreadyClosed = sessionClosed
        sessionClosed = true
        condition.signal()
        condition.unlock()
        guard !alreadyClosed else { return }
        onClosed?()

        logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms close() at stage=\(self.stage, privacy: .public) chunksReceived=\(self.receiveCount) wroteToDevice=\(self.wroteFirstToDevice)")

        // Tell the device we're done. Previously sent nothing here — on
        // device, that showed up as Safari's own ~30s connect timeout
        // firing, then the device retransmitting an unacknowledged FIN
        // with growing backoff forever, since nothing ever answered it.
        // Not a full RFC close handshake (no FIN_WAIT/LAST_ACK tracking —
        // this session is being torn down regardless), just enough for the
        // device's kernel to see a FIN from us and stop waiting.
        seqLock.lock()
        let finPacket = buildTCPPacket(
            srcIP: dstIP, dstIP: srcIP,
            srcPort: dstPort, dstPort: key.srcPort,
            seq: serverSeq, ack: clientSeq,
            flags: 0x11, payload: Data()
        )
        seqLock.unlock()
        flow.writePackets([finPacket], withProtocols: [NSNumber(value: AF_INET)])

        let fd = proxyFD
        if fd != -1 {
            shutdown(fd, SHUT_RDWR)
            Darwin.close(fd)
        }
        tlsListener?.cancel()
        upstream?.cancel()
    }

    func writeToDevice(_ data: Data) {
        // proxyToDevice's recv loop only checks sessionClosed at the top of
        // its while loop — a Darwin.recv() already in flight when close()
        // sends the synthetic FIN would otherwise still deliver its bytes
        // here afterward, so the device sees real payload after (or
        // interleaved with) the FIN. A real TCP stack treats that as a
        // protocol violation and answers with RST — the same failure this
        // FIN was added to eliminate.
        guard !sessionClosed else { return }
        seqLock.lock(); defer { seqLock.unlock() }
        let packet = buildTCPPacket(
            srcIP: dstIP, dstIP: srcIP,
            srcPort: dstPort, dstPort: key.srcPort,
            seq: serverSeq, ack: clientSeq,
            flags: 0x18, payload: data
        )
        // First reply is the TLS server's ServerHello flight heading back to
        // the device. Its seq/ack pair is what to compare against the ack
        // numbers in the device's pure-ACK packets (logged by
        // PacketForwarder): if the device acks past this seq, it accepted
        // the data; if it keeps acking the SYN-ACK's seq, it never saw it.
        if !wroteFirstToDevice {
            wroteFirstToDevice = true
            logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms first write to device: \(data.count) bytes seq=\(self.serverSeq) ack=\(self.clientSeq)")
        }
        serverSeq = serverSeq &+ UInt32(truncatingIfNeeded: data.count)
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
        let closedDuringWait = sessionClosed
        condition.unlock()

        let parsedSNI = parseSNI(from: snapshot)
        let sni = parsedSNI ?? dstIP
        // Empty snapshot here == the 10s wait expired with nothing from the
        // device: the SYN-ACK was never accepted (or Safari never sent a
        // ClientHello). Note the session still proceeds with sni=dstIP, so a
        // cert gets minted for a bare IP and the upstream connect still runs.
        stage = "clientHelloWait"
        logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms ClientHello wait done: \(snapshot.count) bytes buffered, sni=\(parsedSNI ?? "<none, using dstIP>", privacy: .public), closedDuringWait=\(closedDuringWait)")

        if SharedSettings.tlsBypassList.contains(where: { sni == $0 || sni.hasSuffix(".\($0)") }) {
            stage = "bypassed"
            logger.debug("[\(self.tag, privacy: .public)] sni=\(sni, privacy: .public) is on the bypass list — closing (device gets no RST, its socket is now orphaned)")
            close(); return
        }

        stage = "identity"
        let identity: SecIdentity
        do {
            identity = try certCache.identity(for: sni)
        } catch {
            logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms DROP: leaf identity for \(sni, privacy: .public) failed: \(String(describing: error), privacy: .public)")
            dropSession("Leaf certificate for \(sni) failed: \(error.localizedDescription)")
            close(); return
        }
        logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms leaf identity ready for \(sni, privacy: .public)")

        // Build NWListener with the per-domain leaf identity
        let tlsOpts = NWProtocolTLS.Options()
        guard let secIdent = sec_identity_create(identity) else {
            logger.debug("[\(self.tag, privacy: .public)] DROP: sec_identity_create returned nil")
            dropSession("sec_identity_create returned nil for \(sni)")
            close(); return
        }
        sec_protocol_options_set_local_identity(tlsOpts.securityProtocolOptions, secIdent)
        sec_protocol_options_set_peer_authentication_required(
            tlsOpts.securityProtocolOptions, false)

        let listenerParams = NWParameters(tls: tlsOpts, tcp: NWProtocolTCP.Options())

        stage = "listenerCreate"
        let lst: NWListener
        do { lst = try NWListener(using: listenerParams) } catch {
            logger.debug("[\(self.tag, privacy: .public)] DROP: NWListener init threw: \(String(describing: error), privacy: .public)")
            dropSession("NWListener init threw: \(error.localizedDescription)")
            close(); return
        }
        tlsListener = lst

        // Wait for listener to be ready and capture the ephemeral port
        stage = "listenerReadyWait"
        let listenerSem = DispatchSemaphore(value: 0)
        var listenerPort: UInt16 = 0
        lst.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                listenerPort = lst.port?.rawValue ?? 0
                self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] +\(self?.elapsedMs ?? -1)ms NWListener ready on 127.0.0.1:\(listenerPort)")
                listenerSem.signal()
            case .failed(let err):
                self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] NWListener FAILED: \(String(describing: err), privacy: .public)")
                listenerSem.signal()
            case .cancelled:
                listenerSem.signal()
            case .waiting(let err):
                // Never signals the semaphore — if this is the last line for
                // a session, runSession's thread is parked on listenerSem.
                self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] NWListener waiting (thread stays blocked): \(String(describing: err), privacy: .public)")
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
        // Bounded, not .wait() forever: .waiting never signals this
        // semaphore, so an unbounded wait here would park this thread
        // permanently on a listener that never becomes ready — the device
        // would then sit unacknowledged until its own connect timeout (seen
        // on-device: Safari gives up after ~30s with nothing from us).
        if listenerSem.wait(timeout: .now() + 5) == .timedOut {
            logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms DROP: NWListener never became ready within 5s (stuck in .waiting or never signaled)")
            dropSession("NWListener never became ready within 5s")
            close(); return
        }

        guard listenerPort > 0, !sessionClosed else {
            logger.debug("[\(self.tag, privacy: .public)] DROP: listener not usable — port=\(listenerPort) sessionClosed=\(self.sessionClosed)")
            dropSession("Listener not usable (port=\(listenerPort) sessionClosed=\(sessionClosed))")
            close(); return
        }

        // POSIX socket - connects to NWListener on loopback, bridging raw bytes to TLS
        stage = "posixConnect"
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            logger.debug("[\(self.tag, privacy: .public)] DROP: socket() failed errno=\(errno)")
            dropSession("socket() failed errno=\(errno)")
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
            logger.debug("[\(self.tag, privacy: .public)] DROP: connect(127.0.0.1:\(listenerPort)) failed errno=\(errno)")
            Darwin.close(fd)
            dropSession("connect(127.0.0.1:\(listenerPort)) failed errno=\(errno)")
            close(); return
        }
        proxyFD = fd

        // Wait for NWListener to accept our POSIX connection. Pure loopback,
        // so this should be near-instant; bounded anyway for the same
        // reason as listenerSem above — a stuck accept must not park this
        // thread forever.
        stage = "acceptWait"
        if acceptSem.wait(timeout: .now() + 5) == .timedOut {
            logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms DROP: loopback accept never happened within 5s")
            dropSession("Loopback accept never happened within 5s")
            close(); return
        }
        guard let tlsConn = acceptedConn, !sessionClosed else {
            logger.debug("[\(self.tag, privacy: .public)] DROP: no accepted connection — accepted=\(acceptedConn != nil) sessionClosed=\(self.sessionClosed)")
            dropSession("No accepted loopback connection (accepted=\(acceptedConn != nil))")
            close(); return
        }
        logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms loopback bridge accepted")

        // Connect to the real upstream TLS server
        // Host is a bare IP literal, so Network.framework sends no SNI and
        // validates the server's certificate against the IP — expect
        // `.failed` with a trust error (-9808/-9814 family) for most real
        // sites. `.waiting` is logged but does NOT signal the semaphore, so
        // a session whose last line is "upstream waiting" is parked here.
        stage = "upstreamConnect"
        let upstreamConn = NWConnection(
            host: NWEndpoint.Host(dstIP),
            port: NWEndpoint.Port(rawValue: dstPort)!,
            using: .tls
        )
        upstream = upstreamConn
        let upstreamSem = DispatchSemaphore(value: 0)
        upstreamConn.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] +\(self?.elapsedMs ?? -1)ms upstream TLS to \(self?.dstIP ?? "?", privacy: .public) READY")
                upstreamSem.signal()
            case .failed(let err):
                self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] +\(self?.elapsedMs ?? -1)ms upstream TLS to \(self?.dstIP ?? "?", privacy: .public) FAILED: \(String(describing: err), privacy: .public)")
                upstreamSem.signal()
            case .waiting(let err):
                self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] +\(self?.elapsedMs ?? -1)ms upstream TLS to \(self?.dstIP ?? "?", privacy: .public) waiting (thread stays blocked): \(String(describing: err), privacy: .public)")
            case .cancelled:
                self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] upstream cancelled")
            default: break
            }
        }
        upstreamConn.start(queue: .global())
        // `.waiting` (e.g. no route, slow DNS/TCP handshake to the real
        // destination) never signals this semaphore either — bounded for
        // the same reason as listenerSem above. 10s, longer than the
        // loopback-only waits, since this is a real network connection.
        if upstreamSem.wait(timeout: .now() + 10) == .timedOut {
            logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms DROP: upstream never became ready within 10s (state=\(String(describing: upstreamConn.state), privacy: .public))")
            dropSession("Upstream to \(dstIP):\(dstPort) never became ready within 10s (\(upstreamConn.state))")
            close(); return
        }

        guard case .ready = upstreamConn.state else {
            logger.debug("[\(self.tag, privacy: .public)] DROP: upstream not ready (state=\(String(describing: upstreamConn.state), privacy: .public))")
            dropSession("Upstream to \(dstIP):\(dstPort) not ready (\(upstreamConn.state))")
            close(); return
        }

        // Start the NWListener-accepted connection (triggers TLS handshake with POSIX client)
        // This is the device-facing TLS *server*. `.ready` here means the
        // device's TLS client finished the handshake against our leaf cert
        // (so it trusted the CA). `.failed` with a peer-alert error is the
        // device rejecting the cert — that's the signature of a genuine
        // untrusted-CA rejection, as opposed to a transport-level stall.
        stage = "deviceTLSHandshake"
        tlsConn.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.stage = "bridged"
                self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] +\(self?.elapsedMs ?? -1)ms device-facing TLS READY — device completed handshake with our leaf cert")
            case .failed(let err):
                self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] +\(self?.elapsedMs ?? -1)ms device-facing TLS FAILED: \(String(describing: err), privacy: .public)")
            case .waiting(let err):
                self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] device-facing TLS waiting: \(String(describing: err), privacy: .public)")
            case .cancelled:
                self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] device-facing TLS cancelled")
            default: break
            }
        }
        tlsConn.start(queue: .global())
        condition.lock(); let queuedForTLS = inboundBuffer.count; condition.unlock()
        logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms bridge threads starting; \(queuedForTLS) device bytes queued for the TLS server")

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
        tlsConn.receive(minimumIncompleteLength: 1, maximumLength: 65535) { [weak self] data, _, isDone, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                if self.stage != "decrypting" {
                    self.stage = "decrypting"
                    self.logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms first decrypted request bytes from device: \(data.count) bytes for \(sni, privacy: .public)")
                }
                onDecryptedRequest(data, sni)
                upstream.send(content: data, completion: .idempotent)
            }
            if !isDone && !self.sessionClosed {
                self.receiveFromTLS(tlsConn: tlsConn, sni: sni, upstream: upstream,
                                    onDecryptedRequest: onDecryptedRequest)
            } else {
                self.logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms device-facing TLS receive ended: isDone=\(isDone) error=\(String(describing: error), privacy: .public)")
                self.close()
            }
        }
    }

    // Upstream response → NWListener (re-encrypts and sends through POSIX fd to device)
    private func receiveFromUpstream(upstream: NWConnection, tlsConn: NWConnection) {
        upstream.receive(minimumIncompleteLength: 1, maximumLength: 65535) { [weak self] data, _, isDone, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                tlsConn.send(content: data, completion: .idempotent)
            }
            if !isDone && !self.sessionClosed {
                self.receiveFromUpstream(upstream: upstream, tlsConn: tlsConn)
            } else {
                self.logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms upstream receive ended: isDone=\(isDone) error=\(String(describing: error), privacy: .public)")
                self.close()
            }
        }
    }

    // MARK: - Packet builder

    // Spike (todo.md item 1): checksums were previously left as 0x0000 on
    // every synthetic packet this class sends. That's only valid for UDP's
    // own checksum field under IPv4 — the IPv4 header checksum and the TCP
    // checksum are both verified by the receiving device's kernel (utun
    // sets no checksum-offload flags), so a zero checksum here is
    // indistinguishable from a corrupt packet and gets silently dropped.
    // If that's the actual blocker, no synthetic packet from this class —
    // including sendSYNACK() — has ever been accepted by the device.
    //
    // `options` is raw TCP option bytes appended after the fixed 20-byte
    // header (e.g. the MSS option in the SYN-ACK). It is padded with EOL
    // (0x00) to a 4-byte boundary and the data-offset nibble is derived
    // from the resulting header length — so the offset byte is 0x50 only for
    // the no-options case, not hardcoded.
    private func buildTCPPacket(srcIP: String, dstIP: String,
                                 srcPort: UInt16, dstPort: UInt16,
                                 seq: UInt32, ack: UInt32,
                                 flags: UInt8, payload: Data,
                                 options: Data = Data()) -> Data {
        var opts = options
        while opts.count % 4 != 0 { opts.append(0x00) }
        precondition(opts.count <= 40, "TCP options exceed the 40-byte maximum")
        let tcpHeaderLen = 20 + opts.count                     // multiple of 4, 20...60
        let dataOffsetByte = UInt8(tcpHeaderLen / 4) << 4      // upper nibble = header words

        let tcpLen   = UInt16(tcpHeaderLen + payload.count)
        let totalLen = UInt16(20 + tcpLen)
        var p = Data(capacity: Int(totalLen))
        p.append(0x45); p.append(0x00)
        p.appendBE16(totalLen)
        p.appendBE16(0x0000)
        p.appendBE16(0x4000)
        p.append(64); p.append(6); p.appendBE16(0x0000)   // IP header checksum patched below
        p.append(ipOctets: srcIP)
        p.append(ipOctets: dstIP)
        p.appendBE16(srcPort); p.appendBE16(dstPort)
        p.appendBE32(seq); p.appendBE32(ack)
        p.append(dataOffsetByte)
        p.append(flags)
        p.appendBE16(65535); p.appendBE16(0x0000); p.appendBE16(0x0000)  // TCP checksum patched below
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
        session.onClosed = { [weak self] in
            guard let self else { return }
            self.lock.lock()
            // Only remove if this session is still the one registered for the
            // key — closeSession(for:) may have already removed (and
            // replaced) it, e.g. a device FIN arriving right as this session
            // was independently timing out.
            if self.sessions[key] === session { self.sessions.removeValue(forKey: key) }
            self.lock.unlock()
        }
        lock.lock(); sessions[key] = session; lock.unlock()
        session.sendSYNACK()
        session.start(onDecryptedRequest: onDecryptedRequest)
    }

    func hasSession(for key: SessionKey) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return sessions[key] != nil
    }

    // Called when PacketForwarder sees the device retransmit its SYN on a
    // key that already has a session — the original sendSYNACK() was never
    // accepted, so retry it rather than leaving the flow wedged.
    func resendSYNACK(for key: SessionKey) {
        lock.lock(); let s = sessions[key]; lock.unlock()
        s?.sendSYNACK()
    }

    func deliver(_ data: Data, seq: UInt32, for key: SessionKey) {
        lock.lock(); let s = sessions[key]; lock.unlock()
        s?.receive(data, seq: seq)
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
