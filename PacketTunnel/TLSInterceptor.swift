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
    // Deliberately not requiring bytes.count >= 5 + recLen (the full
    // declared TLS record length) here: a modern TLS 1.3 ClientHello with a
    // post-quantum hybrid key-share extension routinely exceeds one TCP
    // segment (e.g. a real 1554-byte ClientHello arriving as 1460 + 94
    // bytes), and the SNI extension sits well before the end of the
    // record; requiring the whole thing up front discarded a real,
    // already-buffered SNI on every such ClientHello, silently falling
    // back to dstIP. Every later field access below already has its own
    // bounds check (`guard i + ... <= bytes.count`), so parsing just stops
    // and returns nil if we genuinely don't have enough bytes yet to reach
    // the SNI extension, so there is no need for this to be checked twice, and this
    // copy of the check was actively wrong for the truncated-buffer case.
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
    // Guards only `cache`/`insertionOrder`, held just long enough to read or
    // write a dictionary entry, never across makeIdentity().
    private let cacheLock = NSLock()
    // One lock per domain, created on first use and never removed (even
    // once that domain is evicted from `cache`), so first-time cert minting
    // for one domain (CA lookup, DER subject parse, key generation, and the
    // dummy ECDSA test signature in verifyUsable, all inside makeIdentity)
    // never blocks a concurrent first-time mint for a different domain. A
    // single shared lock around the whole identity(for:) body previously
    // serialized every domain's mint against every other's: a page pulling
    // from several third-party domains at once queued each one's cert-mint
    // behind every other concurrent one instead of running independently.
    // Same domain still serializes against itself, which is required (two
    // concurrent first-time lookups for one domain must not double-mint/
    // double-write its keychain items) and also against the domain's own
    // eviction cleanup below. Never removing a domain's lock on eviction is
    // deliberate: an evicted domain's NSLock instance must stay the one and
    // only lock anyone (a re-mint, or the eviction that just happened) ever
    // acquires for that domain string, or eviction cleanup and a re-mint of
    // the same just-evicted domain could hold two different locks and run
    // concurrently, doubly-writing (or deleting out from under) the same
    // keychain tag. The set of distinct domains ever seen is small and
    // bounded relative to a device's lifetime; purge() clears this too.
    private var domainLocks: [String: NSLock] = [:]
    private let domainLocksLock = NSLock()

    private func lock(forDomain domain: String) -> NSLock {
        domainLocksLock.lock(); defer { domainLocksLock.unlock() }
        if let existing = domainLocks[domain] { return existing }
        let new = NSLock()
        domainLocks[domain] = new
        return new
    }

    func identity(for domain: String) throws -> SecIdentity {
        cacheLock.lock()
        if let id = cache[domain] { cacheLock.unlock(); return id }
        cacheLock.unlock()

        let domainLock = lock(forDomain: domain)
        domainLock.lock(); defer { domainLock.unlock() }

        // Re-check: another thread may have minted this domain's identity
        // between the unlocked check above and acquiring domainLock.
        cacheLock.lock()
        if let id = cache[domain] { cacheLock.unlock(); return id }
        cacheLock.unlock()

        let id = try makeIdentity(domain: domain)

        cacheLock.lock()
        cache[domain] = id
        insertionOrder.append(domain)
        var evicted: String?
        if insertionOrder.count > Self.maxSize {
            evicted = insertionOrder.removeFirst()
            if let evicted { cache.removeValue(forKey: evicted) }
        }
        cacheLock.unlock()
        // Deleting the evicted domain's keychain items here, under our own
        // domainLock, would be the wrong lock: a concurrent identity(for:)
        // for that same evicted domain acquires ITS OWN domain lock, not
        // ours, so the two could interleave (its fresh SecItemAdd racing
        // this SecItemDelete, or this delete running after it re-inserted
        // into `cache`, wiping out keychain items `cache` still points at).
        // Acquiring the evicted domain's own lock (the same NSLock instance
        // any re-mint of it also acquires, since domain locks are never
        // removed) and re-checking `cache` under it closes that race: if a
        // re-mint won the lock first and is now cached again, its keychain
        // items must survive, so the delete is skipped.
        if let evicted {
            let evictedLock = lock(forDomain: evicted)
            evictedLock.lock()
            cacheLock.lock()
            let stillEvicted = cache[evicted] == nil
            cacheLock.unlock()
            if stillEvicted {
                KeychainStore.deleteAllLeafItems(domains: [evicted])
            }
            evictedLock.unlock()
        }
        return id
    }

    private func makeIdentity(domain: String) throws -> SecIdentity {
        guard let caKey = KeychainStore.loadCAKey() else {
            throw TLSInterceptorError.caKeyMissing
        }
        // The leaf's issuer must be the CA certificate's subject, byte for
        // byte: the device builds the chain from the leaf to the installed
        // CA by that name.
        guard let caCert = KeychainStore.loadCACert(),
              let issuer = X509CertBuilder.subjectName(fromCertificateDER: SecCertificateCopyData(caCert) as Data)
        else {
            throw TLSInterceptorError.caCertMissing
        }
        let tag = Data("mdns.leaf.\(domain)".utf8)
        SecItemDelete([
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessGroup as String: KeychainStore.accessGroup
        ] as CFDictionary)
        // kSecAttrIsPermanent/ApplicationTag/AccessGroup are scoped under
        // kSecPrivateKeyAttrs deliberately, not left at the top level: for
        // SecKeyCreateRandomKey generating an EC key PAIR, top-level
        // attributes apply to BOTH halves unless overridden per-half, which
        // persists the public key to keychain too, under the exact same
        // application tag as the private key. Two keychain items (one
        // public, one private) sharing one tag is exactly the ambiguity
        // that let identity lookup return the public half as if it were the
        // signing key. Confirmed on-device via LeafCertCache.verifyUsable:
        // SecIdentityCopyPrivateKey reported kSecAttrKeyClass=0 (public;
        // Security framework represents kSecAttrKeyClassPublic as the
        // literal string "0" and Private as "1") and canSign=0, exactly
        // matching a public key handed back in place of the private one.
        // The public key here only ever needs to exist in memory long
        // enough to embed in the leaf's SPKI below; it never needs its own
        // keychain item.
        let keyAttrs: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String:    true,
                kSecAttrAccessGroup as String:    KeychainStore.accessGroup,
                kSecAttrApplicationTag as String: tag
            ]
        ]
        var cfErr: Unmanaged<CFError>?
        guard let leafPrivKey = SecKeyCreateRandomKey(keyAttrs as CFDictionary, &cfErr) else {
            throw cfErr!.takeRetainedValue() as Error
        }
        guard let leafPubKey = SecKeyCopyPublicKey(leafPrivKey) else {
            throw TLSInterceptorError.cannotExtractPublicKey
        }
        let certDER = try X509CertBuilder.buildLeafCert(
            domain: domain, leafPublicKey: leafPubKey, caPrivateKey: caKey, issuer: issuer
        )
        guard let cert = SecCertificateCreateWithData(nil, certDER as CFData) else {
            throw TLSInterceptorError.certCreationFailed
        }
        try KeychainStore.saveLeafCert(cert, domain: domain)
        guard let id = KeychainStore.loadLeafIdentity(domain: domain) else {
            throw TLSInterceptorError.identityLookupFailed
        }
        try Self.verifyUsable(id, expectedLeafDER: certDER, domain: domain)
        return id
    }

    /// The device-facing TLS server's first flight (ServerHello …
    /// CertificateVerify … Finished) is produced as one unit, and
    /// CertificateVerify needs an ECDSA-SHA256 signature from this identity's
    /// private key. If that signature can't be produced, Network.framework
    /// aborts while processing the ClientHello: the accepted connection's
    /// receive completes with `-9858: handshake failed` while its state is
    /// still `.preparing`, and not one byte reaches the device: the exact
    /// on-device signature of the duckduckgo.com failure. Reproduced on macOS
    /// with a `kSecClassIdentity` lookup that returned an identity whose key
    /// was not the leaf's: same error, same state, no ServerHello; the same
    /// keychain-backed key correctly paired with the leaf completed the
    /// handshake. So check both things here, before the identity is cached:
    /// the identity's certificate is byte-for-byte the leaf just minted, and
    /// its private key signs the way boringssl will ask it to. A failure is
    /// thrown with the detail (which certificate came back, why signing
    /// failed) so runSession's catch records it in Settings via dropSession.
    private static func verifyUsable(_ id: SecIdentity, expectedLeafDER: Data, domain: String) throws {
        var certRef: SecCertificate?
        SecIdentityCopyCertificate(id, &certRef)
        guard let idCert = certRef else {
            throw TLSInterceptorError.identityMismatch("identity for \(domain) has no certificate")
        }
        let idDER = SecCertificateCopyData(idCert) as Data
        guard idDER == expectedLeafDER else {
            let got = SecCertificateCopySubjectSummary(idCert) as String? ?? "<unreadable>"
            throw TLSInterceptorError.identityMismatch(
                "identity lookup for \(domain) returned certificate '\(got)' (\(idDER.count) B), not the minted leaf (\(expectedLeafDER.count) B)")
        }
        var keyRef: SecKey?
        SecIdentityCopyPrivateKey(id, &keyRef)
        guard let key = keyRef else {
            throw TLSInterceptorError.identityKeyUnusable("identity for \(domain) has no private key")
        }
        let attrs = (SecKeyCopyAttributes(key) as? [String: Any]) ?? [:]
        let keyClass = String(describing: attrs[kSecAttrKeyClass as String] ?? "?")
        let canSign  = String(describing: attrs[kSecAttrCanSign as String] ?? "?")
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureDigestX962SHA256   // what boringssl asks for
        guard SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
            throw TLSInterceptorError.identityKeyUnusable(
                "key for \(domain) reports ECDSA-SHA256 signing unsupported (keyClass=\(keyClass) canSign=\(canSign))")
        }
        var cfErr: Unmanaged<CFError>?
        let digest = Data(count: 32)
        guard SecKeyCreateSignature(key, algorithm, digest as CFData, &cfErr) != nil else {
            let reason = cfErr.map { String(describing: $0.takeRetainedValue()) } ?? "unknown error"
            throw TLSInterceptorError.identityKeyUnusable(
                "test signature with key for \(domain) failed: \(reason) (keyClass=\(keyClass) canSign=\(canSign))")
        }
    }

    func purge() {
        cacheLock.lock()
        let domains = Array(cache.keys)
        cache.removeAll()
        insertionOrder.removeAll()
        cacheLock.unlock()
        domainLocksLock.lock()
        domainLocks.removeAll()
        domainLocksLock.unlock()
        KeychainStore.deleteAllLeafItems(domains: domains)
    }
}

// MARK: - Error types

enum TLSInterceptorError: Error, LocalizedError {
    case caKeyMissing
    case caCertMissing
    case cannotExtractPublicKey
    case certCreationFailed
    case identityLookupFailed
    // The identity the keychain handed back is not usable as a TLS server
    // identity for this leaf: wrong certificate, or a private key that can't
    // produce the ECDSA signature the handshake needs. See
    // LeafCertCache.verifyUsable for why either one presents on device as
    // "-9858: handshake failed" with the connection still `.preparing`.
    case identityMismatch(String)
    case identityKeyUnusable(String)
    case handshakeFailed(OSStatus)
    case upstreamFailed
    var errorDescription: String? {
        switch self {
        case .caKeyMissing:            return "CA private key not found in keychain"
        case .caCertMissing:           return "CA certificate not found in keychain (or its subject could not be read)"
        case .cannotExtractPublicKey:  return "Cannot extract public key from leaf private key"
        case .certCreationFailed:      return "Failed to create leaf certificate"
        case .identityLookupFailed:    return "Cannot find SecIdentity for leaf cert+key pair"
        case .identityMismatch(let d): return "Leaf identity mismatch: \(d)"
        case .identityKeyUnusable(let d): return "Leaf identity key unusable: \(d)"
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
    // Every packet-capture instrumentation call in this file previously went
    // straight to `flow.writePackets`, never through PacketForwarder's
    // `onPacket`, so none of our synthetic replies (SYN-ACK, ServerHello
    // flight, ACKs, the teardown FIN) ever appeared in a device pcap, only
    // the device's own outbound packets. That one-sided capture is what made
    // the FIN-retransmit-storm investigation impossible to close from a pcap
    // alone: we could prove what the device sent but never what we actually
    // sent back. Optional so existing call sites/tests that don't wire it
    // still compile; nil just means "don't capture," not "don't send."
    var onPacket: PacketHandler?

    // `serverSeq` is the next sequence number we will send; `clientSeq` is
    // the next sequence number we expect from the device (i.e. our ack
    // number). Both are touched from more than one thread (`receive(_:)`
    // runs on PacketForwarder's queue and `writeToDevice(_:)` on the
    // proxyToDevice thread), so every read/modify of them, and the
    // writePackets that consumes the pair, happens under `seqLock`. Holding
    // the lock across the write also keeps our synthetic packets leaving in
    // sequence-number order.
    private var serverSeq: UInt32 = 100_000
    private var clientSeq: UInt32 = 0
    private let seqLock = NSLock()

    private var inboundBuffer = Data()
    private let condition = NSCondition()
    private var sessionClosed = false

    // Diagnostic for todo.md item 1's checksum spike: the decisive
    // question is whether the device's kernel ever ACKs sendSYNACK()'s
    // packet at all. Logged once, not every packet: `receive(_:)` fires on
    // every inbound chunk, and this session lives across an entire TLS
    // connection's worth of them.
    private let logger = Logger(subsystem: "com.mDNSShark.PacketTunnel", category: "TLSInterceptor")
    private var loggedFirstReceive = false

    // Diagnostic scaffolding for the on-device HTTPS-hang investigation
    // (todo.md item 1). `stage` names the last step runSession reached so
    // close() can report *where* a session died; every guard in
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
    // other and with runSession's own thread). Lock-protected so a
    // diagnostic meant to answer "which stage did we die at" doesn't itself
    // race.
    private var _stage = "opened"
    private let stageLock = NSLock()
    private var stage: String {
        get { stageLock.lock(); defer { stageLock.unlock() }; return _stage }
        set { stageLock.lock(); defer { stageLock.unlock() }; _stage = newValue }
    }
    // Last non-ready state either bridge connection reported after
    // runSession handed off to the receive chains. The receive callbacks
    // only see a generic NWError when a connection dies; the state handler
    // saw the specific one (e.g. the TLS alert code). Same threading as
    // `stage`, same lock.
    private var _lastBridgeFailure: String?
    private var lastBridgeFailure: String? {
        get { stageLock.lock(); defer { stageLock.unlock() }; return _lastBridgeFailure }
        set { stageLock.lock(); defer { stageLock.unlock() }; _lastBridgeFailure = newValue }
    }
    private var receiveCount = 0
    private var wroteFirstToDevice = false
    // Set only when the real upstream server has actually sent back
    // application data that we relayed toward the device. Distinct from
    // `stage == "decrypting"`, which flips true the moment the device's
    // *request* is first decrypted and then never resets. Using stage alone
    // in recordBridgeEnd meant any errorless upstream/device-facing EOF after
    // that point was assumed to be a normal finished exchange even if zero
    // response bytes had ever gone back, silently hiding a real stall (seen
    // on-device: full handshake, request relayed, "Last:" stays blank, no
    // response ever reaches Safari).
    // Same lock as `stage`/`lastBridgeFailure`: written from
    // receiveFromUpstream's completion (upstream connection's queue), read
    // from recordBridgeEnd (reachable from either connection's completion,
    // both on .global()); an unguarded var here would be a real data race.
    private var _upstreamRespondedWithData = false
    private var upstreamRespondedWithData: Bool {
        get { stageLock.lock(); defer { stageLock.unlock() }; return _upstreamRespondedWithData }
        set { stageLock.lock(); defer { stageLock.unlock() }; _upstreamRespondedWithData = newValue }
    }
    private let t0 = Date()
    private var elapsedMs: Int { Int(Date().timeIntervalSince(t0) * 1000) }
    private lazy var tag = "\(srcIP):\(key.srcPort)→\(dstIP):\(dstPort)"

    // Network.framework + POSIX bridge
    private var proxyFD: Int32 = -1
    private var tlsListener: NWListener?
    private var upstream: NWConnection?
    // The NWListener-accepted, device-facing connection receiveFromTLS reads
    // from. close() must cancel this too, same as `upstream`. Without it,
    // a session that never sees a natural EOF on the device-facing side
    // (e.g. the device gives up and RSTs instead of the loopback stream
    // ending) leaves that connection's receive() pending forever: never
    // cancelled, never erroring, leaking the connection and never reaching
    // recordBridgeEnd from that side.
    private var deviceTLSConn: NWConnection?

    var lastActivity = Date()

    // Set by TLSInterceptor.openSession right after construction. close() was
    // previously only ever removed from TLSInterceptor.sessions by the
    // device-FIN/RST path (closeSession(for:)): a session that closes itself
    // (e.g. one of the bounded listener/accept/upstream timeouts) left a dead
    // entry keyed by the same 4-tuple, so a device SYN retransmit on that key
    // found hasSession(for:) still true and PacketForwarder just logged it
    // instead of ever retrying the handshake; the flow stayed wedged until
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

    // Single choke point for every synthetic packet this session sends to
    // the device; see `onPacket`'s doc comment for why this exists.
    private func sendToDevice(_ packet: Data) {
        flow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
        onPacket?(packet, .inbound, true)
    }

    // MSS option advertised in our SYN-ACK: kind=2, len=4, value=1460 (0x05B4)
    // big-endian. Without it the device's kernel falls back to
    // tcp_mssdflt (512), which the pcap showed as a 1512-byte ClientHello
    // arriving in three 512-byte segments. 1460 is the standard Ethernet
    // value; the tunnel MTU is at least that, and the bytes never touch a
    // real wire anyway; they go straight into inboundBuffer.
    private static let advertisedMSS = 1460
    private static let mssOption: Data = Data([0x02, 0x04, 0x05, 0xB4])

    // The ISN used for the SYN-ACK, fixed on the first call. A retransmitted
    // SYN-ACK (PacketForwarder.resendSYNACK, when the device retries its SYN
    // because the first one was rejected) must reuse this exact value:
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
        sendToDevice(packet)
    }

    /// `seq` is the TCP sequence number PacketForwarder read from the
    /// device's packet header. A segment whose `seq` doesn't match
    /// `clientSeq` (a retransmit, or reordering) is dropped rather than
    /// blindly appended: accepting it would advance `clientSeq` past bytes
    /// the device never actually sent, making our next ack invalid on the
    /// device's side: its kernel would treat that as unacceptable (RFC
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
        sendToDevice(ackPacket)
        seqLock.unlock()

        guard inWindow else { return }

        condition.lock()
        inboundBuffer.append(data)
        let buffered = inboundBuffer.count
        lastActivity = Date()
        condition.signal()
        condition.unlock()

        // First real bytes back from the device is the proof the SYN-ACK
        // was accepted and the kernel completed its handshake; if the
        // checksum fix didn't work, this never fires for this session.
        if !loggedFirstReceive {
            loggedFirstReceive = true
            logger.debug("first device bytes received for \(self.srcIP, privacy: .public):\(self.key.srcPort) → \(self.dstIP, privacy: .public):\(self.dstPort) (\(data.count) bytes): handshake completed")
        }
        receiveCount += 1
        if receiveCount <= 6 {
            let head = data.prefix(6).map { String(format: "%02x", $0) }.joined(separator: " ")
            logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms device chunk #\(self.receiveCount): \(data.count) bytes head=\(head, privacy: .public) buffered=\(buffered) stage=\(self.stage, privacy: .public)")
        }
    }

    // Records *why* a session was dropped, not just that one was. The
    // Settings screen already shows a running drop count
    // (SharedSettings.tlsInterceptorDropCount) with no reason attached, and
    // on-device Console access has repeatedly been unreliable for reading
    // the per-guard debug log lines below. This makes the last failure
    // visible from the app itself.
    private func dropSession(_ reason: String) {
        SharedSettings.tlsInterceptorLastError = reason
        SharedSettings.incrementDropCount()
    }

    // The two receive chains (receiveFromTLS / receiveFromUpstream) are the
    // only paths after the ClientHello that used to close() without going
    // through dropSession, so a session dying in the bridge phase (e.g.
    // the device-facing TLS handshake failing before a ServerHello ever
    // left) incremented nothing and left "Last:" blank in Settings, while
    // the packet capture showed every attempt ending in our FIN. Seen on
    // device: 20+ consecutive duckduckgo.com sessions, each closed ~100 ms
    // after the ClientHello (right after the upstream connect), zero
    // diagnostics. Records the reason unless this callback is merely the
    // echo of a close() that already happened (cancel() makes both chains
    // end with an error), or the exchange had genuinely finished.
    private func recordBridgeEnd(side: String, isDone: Bool, error: NWError?, state: NWConnection.State) {
        guard !sessionClosed else { return }
        let stage = self.stage
        // A clean EOF is the normal end of an HTTP exchange only if the
        // upstream server actually sent back application data at some point.
        // `stage == "decrypting"` (the old check here) flips true the
        // moment the device's own *request* is first decrypted and never
        // resets, so it can't tell "exchange finished" apart from "upstream
        // silently never responded."
        if error == nil && upstreamRespondedWithData { return }
        let failure = lastBridgeFailure.map { " last=\($0)" } ?? ""
        dropSession("\(side) ended at stage=\(stage): isDone=\(isDone) error=\(error.map { String(describing: $0) } ?? "none") state=\(state)\(failure) respondedWithData=\(upstreamRespondedWithData)")
    }

    /// `deviceFINSeq`: when the device itself initiated the close (a FIN
    /// arrived), this is that FIN's own sequence number. A FIN consumes one
    /// sequence number same as real data, but the FIN packet carries no
    /// payload and never goes through `receive(_:seq:)`, so `clientSeq` was
    /// never advanced past it. Replying with the stale `clientSeq` acks one
    /// byte short of the device's FIN, which its kernel doesn't recognize as
    /// acknowledging that FIN at all. Confirmed on-device: the device
    /// re-sent the same FIN 12+ times over ~18s (growing backoff) before
    /// finally giving up with an RST, even though our reply otherwise
    /// arrived fine. Passing the FIN's own seq here lets close() ack
    /// `deviceFINSeq + 1`, the value the device is actually waiting for.
    func close(deviceFINSeq: UInt32? = nil) {
        condition.lock()
        let alreadyClosed = sessionClosed
        sessionClosed = true
        condition.signal()
        condition.unlock()

        // Handled before the `alreadyClosed` guard, and sent even when this
        // call turns out to be a no-op below: a *simultaneous* close is a
        // real, common case here, not an edge case: the upstream server
        // finishing its response triggers our own close() (deviceFINSeq nil)
        // at essentially the same moment the device, having gotten what it
        // wanted, sends its own FIN. Confirmed on-device: our FIN (sent first,
        // acking only what we'd received *before* the device's FIN) and the
        // device's FIN crossed on the wire seconds apart. Once alreadyClosed
        // is true, nothing below this block runs again, so if the seq bump
        // and the ack it requires stayed gated behind that guard (as they
        // did before), the device's FIN would never get acked at all,
        // reproducing the exact retransmit-storm-then-RST failure this
        // parameter exists to prevent, just for the simultaneous-close case
        // instead of the plain device-closes-first one.
        if let deviceFINSeq {
            seqLock.lock()
            let bumped = max(clientSeq, deviceFINSeq &+ 1)
            let advanced = bumped != clientSeq
            clientSeq = bumped
            let ackPacket = advanced ? buildTCPPacket(
                srcIP: dstIP, dstIP: srcIP,
                srcPort: dstPort, dstPort: key.srcPort,
                seq: serverSeq, ack: clientSeq,
                flags: 0x10, payload: Data()
            ) : nil
            seqLock.unlock()
            if let ackPacket { sendToDevice(ackPacket) }
        }

        guard !alreadyClosed else { return }
        onClosed?()

        logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms close() at stage=\(self.stage, privacy: .public) chunksReceived=\(self.receiveCount) wroteToDevice=\(self.wroteFirstToDevice)")

        // Tell the device we're done. Previously sent nothing here; on
        // device, that showed up as Safari's own ~30s connect timeout
        // firing, then the device retransmitting an unacknowledged FIN
        // with growing backoff forever, since nothing ever answered it.
        // Not a full RFC close handshake (no FIN_WAIT/LAST_ACK tracking;
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
        sendToDevice(finPacket)

        let fd = proxyFD
        if fd != -1 {
            shutdown(fd, SHUT_RDWR)
            Darwin.close(fd)
        }
        tlsListener?.cancel()
        upstream?.cancel()
        deviceTLSConn?.cancel()
    }

    /// Snapshot of the sequence number this session next expects from the
    /// device, i.e. how far its inbound stream has actually been accepted
    /// so far. Lets a caller (PacketForwarder's FIN handling) tell a
    /// genuinely-accepted FIN apart from one whose coalesced payload was
    /// rejected as out-of-window, without duplicating receive(_:seq:)'s own
    /// in-window bookkeeping.
    func currentClientSeq() -> UInt32 {
        seqLock.lock(); defer { seqLock.unlock() }
        return clientSeq
    }

    func writeToDevice(_ data: Data) {
        // proxyToDevice's recv loop only checks sessionClosed at the top of
        // its while loop. A Darwin.recv() already in flight when close()
        // sends the synthetic FIN would otherwise still deliver its bytes
        // here afterward, so the device sees real payload after (or
        // interleaved with) the FIN. A real TCP stack treats that as a
        // protocol violation and answers with RST, the same failure this
        // FIN was added to eliminate.
        guard !sessionClosed else { return }
        seqLock.lock(); defer { seqLock.unlock() }

        // Split into MSS-sized segments instead of one packet holding the
        // whole payload. A real response easily runs past 1460 bytes (an
        // 11KB duckduckgo results page, confirmed on-device), and a single
        // oversized synthetic segment silently violates both the MSS we
        // advertised in our own SYN-ACK and the tunnel's 1500-byte MTU: the
        // device's kernel just never acks it, which looked identical to "no
        // response ever arrived" until packet capture covered our own
        // outbound packets and made the oversized segment visible at all.
        var offset = data.startIndex
        var first = true
        while offset < data.endIndex {
            let end = data.index(offset, offsetBy: Self.advertisedMSS, limitedBy: data.endIndex) ?? data.endIndex
            let chunk = data[offset..<end]
            let packet = buildTCPPacket(
                srcIP: dstIP, dstIP: srcIP,
                srcPort: dstPort, dstPort: key.srcPort,
                seq: serverSeq, ack: clientSeq,
                flags: 0x18, payload: Data(chunk)
            )
            // First reply is the TLS server's ServerHello flight heading back
            // to the device. Its seq/ack pair is what to compare against the
            // ack numbers in the device's pure-ACK packets (logged by
            // PacketForwarder): if the device acks past this seq, it
            // accepted the data; if it keeps acking the SYN-ACK's seq, it
            // never saw it.
            if first, !wroteFirstToDevice {
                wroteFirstToDevice = true
                logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms first write to device: \(data.count) bytes seq=\(self.serverSeq) ack=\(self.clientSeq)")
            }
            first = false
            serverSeq = serverSeq &+ UInt32(truncatingIfNeeded: chunk.count)
            sendToDevice(packet)
            offset = end
        }
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
            logger.debug("[\(self.tag, privacy: .public)] sni=\(sni, privacy: .public) is on the bypass list; closing (device gets no RST, its socket is now orphaned)")
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

        // Pin the listener to loopback explicitly. Left at its default the
        // listener binds the wildcard address, and inside a packet-tunnel
        // provider that is not a neutral choice: NECP's VPN-loop-prevention
        // policy scopes this process's sockets to the physical interface
        // (en0/pdp_ip0) so the provider's own traffic never re-enters the
        // tunnel. A wildcard-bound listener gets that scope (the kernel's
        // loopback bypass only applies to sockets whose local/remote
        // address is loopback or that are bound to lo0, not to 0.0.0.0),
        // and every connection it accepts inherits it (xnu tcp_input:
        // "Inherit INP_BOUND_IF from listener"). The accepted socket's
        // SYN-ACK to 127.0.0.1 then fails source-interface selection in
        // ip_output (127.0.0.1 is not an address of en0 → EADDRNOTAVAIL)
        // and is dropped silently, so posixConnect below sees no reply and
        // fails with ETIMEDOUT (errno 60), the exact reason recorded in
        // SharedSettings.tlsInterceptorLastError on device, 91/91 drops.
        // Refused (61) would have meant "no listener"; timed out means
        // "listener heard us and could not answer". Both settings below
        // put the listener on the loopback path the kernel exempts from
        // scoping: a loopback local address takes NECP's loopback bypass,
        // and an lo0 scope is treated as unscoped for routing.
        listenerParams.requiredInterfaceType = .loopback
        listenerParams.requiredLocalEndpoint = NWEndpoint.hostPort(host: .ipv4(.loopback), port: .any)

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
                // Never signals the semaphore; if this is the last line for
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
        // permanently on a listener that never becomes ready; the device
        // would then sit unacknowledged until its own connect timeout (seen
        // on-device: Safari gives up after ~30s with nothing from us).
        if listenerSem.wait(timeout: .now() + 5) == .timedOut {
            logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms DROP: NWListener never became ready within 5s (stuck in .waiting or never signaled)")
            dropSession("NWListener never became ready within 5s")
            close(); return
        }

        guard listenerPort > 0, !sessionClosed else {
            logger.debug("[\(self.tag, privacy: .public)] DROP: listener not usable: port=\(listenerPort) sessionClosed=\(self.sessionClosed)")
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

        // Bounded like every other wait in this function. A blocking
        // connect() whose SYN gets no answer sits in the kernel for its
        // full SYN-retransmit budget (~75s on iOS) before ETIMEDOUT; on
        // device that parked this thread and left the device's socket
        // hanging for over a minute per session. Non-blocking connect +
        // poll() gives it the same 5s the listener/accept waits get. The
        // fd is put back into blocking mode on success because
        // deviceToProxy/proxyToDevice rely on blocking send/recv.
        let savedFlags = fcntl(fd, F_GETFL)
        _ = fcntl(fd, F_SETFL, savedFlags | O_NONBLOCK)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        // Read errno before anything else runs: the previous version logged
        // and close()d first, both of which may overwrite it, so the value
        // that reached the Settings diagnostic was not guaranteed to be
        // connect()'s own.
        var connectErrno: Int32 = (rc == 0) ? 0 : errno
        if rc != 0 && connectErrno == EINPROGRESS {
            var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let ready = poll(&pfd, 1, 5000)
            if ready == 0 {
                connectErrno = ETIMEDOUT
            } else if ready < 0 {
                connectErrno = errno
            } else {
                var soErr: Int32 = 0
                var soLen = socklen_t(MemoryLayout<Int32>.size)
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &soErr, &soLen)
                connectErrno = soErr
            }
        }
        _ = fcntl(fd, F_SETFL, savedFlags)

        guard connectErrno == 0 else {
            let desc = String(cString: strerror(connectErrno))
            logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms DROP: connect(127.0.0.1:\(listenerPort)) failed errno=\(connectErrno) (\(desc, privacy: .public))")
            Darwin.close(fd)
            dropSession("connect(127.0.0.1:\(listenerPort)) failed errno=\(connectErrno) (\(desc))")
            close(); return
        }
        proxyFD = fd

        // Wait for NWListener to accept our POSIX connection. Pure loopback,
        // so this should be near-instant; bounded anyway for the same
        // reason as listenerSem above: a stuck accept must not park this
        // thread forever.
        stage = "acceptWait"
        if acceptSem.wait(timeout: .now() + 5) == .timedOut {
            logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms DROP: loopback accept never happened within 5s")
            dropSession("Loopback accept never happened within 5s")
            close(); return
        }
        guard let tlsConn = acceptedConn, !sessionClosed else {
            logger.debug("[\(self.tag, privacy: .public)] DROP: no accepted connection: accepted=\(acceptedConn != nil) sessionClosed=\(self.sessionClosed)")
            dropSession("No accepted loopback connection (accepted=\(acceptedConn != nil))")
            close(); return
        }
        deviceTLSConn = tlsConn
        logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms loopback bridge accepted")

        // Connect to the real upstream TLS server.
        //
        // Connect to the IP the device itself chose (dstIP): the exact
        // server the device resolved, with no second DNS lookup and no risk
        // of a CDN handing this process a different edge. But give the TLS
        // layer the real hostname from the device's ClientHello. Without it
        // the endpoint is an IP literal, Network.framework sends no SNI, and
        // the server's default certificate cannot match an IP. Reproduced on
        // macOS 26 against 52.149.246.39 (Safari's duckduckgo.com endpoint):
        // the bare-IP connection goes `.waiting(-9808: bad certificate
        // format)` within ~400ms and stays there indefinitely. It never
        // reaches `.failed` (since macOS 13 / iOS 16 establishment-time
        // failures are surfaced as `.waiting`, not `.failed`), so the old
        // handler, which only signaled on `.ready`/`.failed`, left every
        // session to die at the 10s timeout below. The same IP with
        // sec_protocol_options_set_tls_server_name(sni) is `.ready` in
        // ~100ms and the negotiated TLS metadata reports server_name == sni:
        // the name drives both the SNI extension and certificate hostname
        // validation (the header describes it as overriding "the server name
        // obtained from the endpoint"; Apple DTS recommends it for exactly
        // this connect-by-IP-with-separate-SNI case). Only set when the
        // device's ClientHello actually carried an SNI; `sni` falls back to
        // dstIP otherwise, and an IP literal is not a legal SNI value
        // (RFC 6066 §3).
        stage = "upstreamConnect"
        let upstreamTLS = NWProtocolTLS.Options()
        if parsedSNI != nil {
            sec_protocol_options_set_tls_server_name(upstreamTLS.securityProtocolOptions, sni)
        }
        let upstreamConn = NWConnection(
            host: NWEndpoint.Host(dstIP),
            port: NWEndpoint.Port(rawValue: dstPort)!,
            using: NWParameters(tls: upstreamTLS, tcp: NWProtocolTCP.Options())
        )
        upstream = upstreamConn
        let upstreamSem = DispatchSemaphore(value: 0)
        // Last state seen before any `.cancelled`, for the timeout diagnostic
        // below. Network.framework only ever reports `.cancelled` for a
        // connection "cancelled by the caller" (connection.h), and the sole
        // caller here is close() → upstream.cancel(). A timeout that reads
        // `.cancelled` therefore means something closed this session from
        // outside runSession (device FIN/RST via closeSession, or stop())
        // before the wait expired; on device that showed up as "never
        // became ready within 10s (cancelled)", hiding what the connection
        // had actually been doing. Written on the connection's queue, read
        // on this thread, hence the lock.
        let upstreamStateLock = NSLock()
        var lastUpstreamState = "none"
        upstreamConn.stateUpdateHandler = { [weak self] state in
            if case .cancelled = state {} else {
                upstreamStateLock.lock()
                lastUpstreamState = String(describing: state)
                upstreamStateLock.unlock()
            }
            switch state {
            case .ready:
                self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] +\(self?.elapsedMs ?? -1)ms upstream TLS to \(self?.dstIP ?? "?", privacy: .public) READY")
                upstreamSem.signal()
            case .failed(let err):
                self?.lastBridgeFailure = "upstream failed: \(err)"
                self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] +\(self?.elapsedMs ?? -1)ms upstream TLS to \(self?.dstIP ?? "?", privacy: .public) FAILED: \(String(describing: err), privacy: .public)")
                upstreamSem.signal()
            case .waiting(.tls(let status)):
                // A TLS-layer error (trust, protocol) is terminal in
                // practice (no path change will make the server's
                // certificate match), but it arrives as `.waiting`, not
                // `.failed` (see above). Signal so the guard below reports
                // the real reason at once instead of after the 10s wait.
                self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] +\(self?.elapsedMs ?? -1)ms upstream TLS to \(self?.dstIP ?? "?", privacy: .public) waiting on TLS error (treated as failed): \(status)")
                upstreamSem.signal()
            case .waiting(let err):
                self?.lastBridgeFailure = "upstream waiting: \(err)"
                self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] +\(self?.elapsedMs ?? -1)ms upstream TLS to \(self?.dstIP ?? "?", privacy: .public) waiting (thread stays blocked): \(String(describing: err), privacy: .public)")
            case .cancelled:
                self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] upstream cancelled")
            default: break
            }
        }
        upstreamConn.start(queue: .global())
        // `.waiting` with a non-TLS error (no route, slow TCP handshake to
        // the real destination) still never signals this semaphore;
        // bounded for the same reason as listenerSem above. 10s, longer
        // than the loopback-only waits, since this is a real network
        // connection.
        if upstreamSem.wait(timeout: .now() + 10) == .timedOut {
            upstreamStateLock.lock(); let last = lastUpstreamState; upstreamStateLock.unlock()
            let closedExternally = sessionClosed
            logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms DROP: upstream never became ready within 10s (state=\(String(describing: upstreamConn.state), privacy: .public) last=\(last, privacy: .public) closedExternally=\(closedExternally))")
            dropSession("Upstream to \(dstIP):\(dstPort) (sni \(sni)) never became ready within 10s (\(upstreamConn.state); last=\(last); closedExternally=\(closedExternally))")
            close(); return
        }

        guard case .ready = upstreamConn.state else {
            logger.debug("[\(self.tag, privacy: .public)] DROP: upstream not ready (state=\(String(describing: upstreamConn.state), privacy: .public))")
            dropSession("Upstream to \(dstIP):\(dstPort) (sni \(sni)) not ready (\(upstreamConn.state))")
            close(); return
        }

        // Start the NWListener-accepted connection (triggers TLS handshake with POSIX client)
        // This is the device-facing TLS *server*. `.ready` here means the
        // device's TLS client finished the handshake against our leaf cert
        // (so it trusted the CA). `.failed` with a peer-alert error is the
        // device rejecting the cert; that's the signature of a genuine
        // untrusted-CA rejection, as opposed to a transport-level stall.
        stage = "deviceTLSHandshake"
        tlsConn.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.stage = "bridged"
                self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] +\(self?.elapsedMs ?? -1)ms device-facing TLS READY: device completed handshake with our leaf cert")
            case .failed(let err):
                self?.lastBridgeFailure = "device-facing TLS failed: \(err)"
                self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] +\(self?.elapsedMs ?? -1)ms device-facing TLS FAILED: \(String(describing: err), privacy: .public)")
            case .waiting(let err):
                self?.lastBridgeFailure = "device-facing TLS waiting: \(err)"
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
                } else {
                    self.logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms decrypted request chunk from device: \(data.count) bytes for \(sni, privacy: .public)")
                }
                onDecryptedRequest(data, sni)
                upstream.send(content: data, completion: .contentProcessed { [weak self] sendError in
                    if let sendError {
                        self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] upstream.send failed: \(String(describing: sendError), privacy: .public)")
                    }
                })
            }
            if !isDone && !self.sessionClosed {
                self.receiveFromTLS(tlsConn: tlsConn, sni: sni, upstream: upstream,
                                    onDecryptedRequest: onDecryptedRequest)
            } else {
                self.logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms device-facing TLS receive ended: isDone=\(isDone) error=\(String(describing: error), privacy: .public)")
                self.recordBridgeEnd(side: "Device-facing TLS for \(sni)", isDone: isDone, error: error, state: tlsConn.state)
                self.close()
            }
        }
    }

    // Upstream response → NWListener (re-encrypts and sends through POSIX fd to device)
    private func receiveFromUpstream(upstream: NWConnection, tlsConn: NWConnection) {
        upstream.receive(minimumIncompleteLength: 1, maximumLength: 65535) { [weak self] data, _, isDone, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                if !self.upstreamRespondedWithData {
                    self.upstreamRespondedWithData = true
                    self.logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms first response bytes from upstream \(self.dstIP, privacy: .public):\(self.dstPort): \(data.count) bytes")
                } else {
                    self.logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms response chunk from upstream: \(data.count) bytes")
                }
                tlsConn.send(content: data, completion: .contentProcessed { [weak self] sendError in
                    if let sendError {
                        self?.logger.debug("[\(self?.tag ?? "?", privacy: .public)] tlsConn.send (to device) failed: \(String(describing: sendError), privacy: .public)")
                    }
                })
            }
            if !isDone && !self.sessionClosed {
                self.receiveFromUpstream(upstream: upstream, tlsConn: tlsConn)
            } else {
                self.logger.debug("[\(self.tag, privacy: .public)] +\(self.elapsedMs)ms upstream receive ended: isDone=\(isDone) error=\(String(describing: error), privacy: .public)")
                self.recordBridgeEnd(side: "Upstream TLS to \(self.dstIP):\(self.dstPort)", isDone: isDone, error: error, state: upstream.state)
                self.close()
            }
        }
    }

    // MARK: - Packet builder

    // Spike (todo.md item 1): checksums were previously left as 0x0000 on
    // every synthetic packet this class sends. That's only valid for UDP's
    // own checksum field under IPv4; the IPv4 header checksum and the TCP
    // checksum are both verified by the receiving device's kernel (utun
    // sets no checksum-offload flags), so a zero checksum here is
    // indistinguishable from a corrupt packet and gets silently dropped.
    // If that's the actual blocker, no synthetic packet from this class,
    // including sendSYNACK(), has ever been accepted by the device.
    //
    // `options` is raw TCP option bytes appended after the fixed 20-byte
    // header (e.g. the MSS option in the SYN-ACK). It is padded with EOL
    // (0x00) to a 4-byte boundary and the data-offset nibble is derived
    // from the resulting header length, so the offset byte is 0x50 only for
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
    // Mirrors the check LeafCertCache.makeIdentity(for:) does before minting any
    // leaf cert: a CA key alone is not enough, since makeIdentity() throws
    // .caCertMissing without a matching CA cert too. PacketForwarder calls this
    // instead of KeychainStore.loadCAKey() != nil so "key pasted but no cert"
    // resolves to a clean not-configured/plain-relay state instead of turning
    // interception on and then failing every session's cert mint.
    static func hasCompleteCAIdentity() -> Bool {
        guard KeychainStore.loadCAKey() != nil else { return false }
        guard let caCert = KeychainStore.loadCACert(),
              X509CertBuilder.subjectName(fromCertificateDER: SecCertificateCopyData(caCert) as Data) != nil
        else { return false }
        return true
    }

    private var sessions: [SessionKey: TLSSession] = [:]
    private let lock = NSLock()
    let certCache = LeafCertCache()
    // Forwarded to every TLSSession so its synthetic replies reach the same
    // pcap capture as the plain-relay path's; see TLSSession.onPacket.
    private let onPacket: PacketHandler?

    init(onPacket: PacketHandler? = nil) {
        self.onPacket = onPacket
    }

    func openSession(key: SessionKey, srcIP: String, dstIP: String,
                     clientISN: UInt32, flow: NEPacketTunnelFlow,
                     onDecryptedRequest: @escaping (Data, String) -> Void) {
        let session = TLSSession(
            key: key, srcIP: srcIP, dstIP: dstIP, dstPort: key.dstPort,
            clientISN: clientISN, flow: flow, certCache: certCache
        )
        session.onPacket = onPacket
        session.onClosed = { [weak self] in
            guard let self else { return }
            self.lock.lock()
            // Only remove if this session is still the one registered for the
            // key: closeSession(for:) may have already removed (and
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
    // key that already has a session: the original sendSYNACK() was never
    // accepted, so retry it rather than leaving the flow wedged.
    func resendSYNACK(for key: SessionKey) {
        lock.lock(); let s = sessions[key]; lock.unlock()
        s?.sendSYNACK()
    }

    func deliver(_ data: Data, seq: UInt32, for key: SessionKey) {
        lock.lock(); let s = sessions[key]; lock.unlock()
        s?.receive(data, seq: seq)
    }

    /// The session's current expected-next-from-device sequence number, or
    /// nil if there's no session for `key`. Call before closeSession(for:)
    /// removes the session, not after.
    func clientSeq(for key: SessionKey) -> UInt32? {
        lock.lock(); let s = sessions[key]; lock.unlock()
        return s?.currentClientSeq()
    }

    func closeSession(for key: SessionKey, deviceFINSeq: UInt32? = nil) {
        lock.lock(); let s = sessions.removeValue(forKey: key); lock.unlock()
        s?.close(deviceFINSeq: deviceFINSeq)
    }

    func stop() {
        lock.lock(); let all = Array(sessions.values); sessions.removeAll(); lock.unlock()
        all.forEach { $0.close() }
        certCache.purge()
    }
}
