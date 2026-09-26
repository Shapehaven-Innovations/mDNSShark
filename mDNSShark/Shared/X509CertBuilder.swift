// mDNSShark/Shared/X509CertBuilder.swift
// Add to both mDNSShark and PacketTunnel targets via Xcode Target Membership.
// Builds minimal DER-encoded X.509 certificates using EC P-256 keys.
import Foundation
import Security

// Minimal DER-encoded X.509 certificate builder using Security.framework for signing.
// Only supports EC P-256 (ecPrime256v1) keys.
enum X509CertBuilder {

    // Pre-encoded OID value bytes (tag 0x06 added by derOID())
    private static let oidECPublicKey:      [UInt8] = [0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01]
    private static let oidPrime256v1:       [UInt8] = [0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07]
    private static let oidEcdsaSHA256:      [UInt8] = [0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02]
    private static let oidCommonName:       [UInt8] = [0x55,0x04,0x03]
    private static let oidBasicConstraints: [UInt8] = [0x55,0x1D,0x13]
    private static let oidSubjectAltName:   [UInt8] = [0x55,0x1D,0x11]
    private static let oidExtKeyUsage:      [UInt8] = [0x55,0x1D,0x25]
    private static let oidServerAuth:       [UInt8] = [0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x01]

    /// Self-signed CA certificate DER. `privateKey` is used for both the SPKI and signing.
    static func buildSelfSignedCA(cn: String, privateKey: SecKey, validDays: Int = 1095) throws -> Data {
        guard let pubKey = SecKeyCopyPublicKey(privateKey) else { throw CertError.cannotExtractPublicKey }
        let tbs = try tbs_CA(cn: cn, publicKey: pubKey, validDays: validDays)
        return try assembleCert(tbs: tbs, signingKey: privateKey)
    }

    /// Leaf certificate DER signed by `caPrivateKey`. `issuer` is the DER-encoded
    /// subject Name of the CA certificate, byte-for-byte (see
    /// `subjectName(fromCertificateDER:)`): RFC 5280 §4.1.2.4 requires the leaf's
    /// issuer field to equal the issuing CA's subject, and the platform's chain
    /// builder locates the issuer by that name — a leaf whose issuer is anything
    /// else fails with errSecCreateChainFailed ("Unable to build chain to root")
    /// even with the CA installed as an anchor.
    static func buildLeafCert(domain: String, leafPublicKey: SecKey, caPrivateKey: SecKey, issuer: Data) throws -> Data {
        let tbs = try tbs_Leaf(domain: domain, publicKey: leafPublicKey, issuer: issuer)
        return try assembleCert(tbs: tbs, signingKey: caPrivateKey)
    }

    /// The DER-encoded subject Name of an X.509 certificate, exactly as encoded
    /// in the certificate, for use as the issuer field of certificates it signs.
    /// Walks TBSCertificate: [0] version (optional), serialNumber, signature,
    /// issuer, validity, subject. Works for any v1–v3 certificate, so it also
    /// covers a user-imported CA whose subject is not a bare CN.
    static func subjectName(fromCertificateDER der: Data) -> Data? {
        let b = [UInt8](der)
        // (contentStart, contentEnd) of the TLV at `i`, or nil if malformed.
        func tlv(_ i: Int) -> (start: Int, end: Int)? {
            guard i + 2 <= b.count else { return nil }
            var p = i + 1
            var len = Int(b[p]); p += 1
            if len & 0x80 != 0 {
                let n = len & 0x7F
                guard n >= 1, n <= 4, p + n <= b.count else { return nil }
                len = 0
                for _ in 0..<n { len = len << 8 | Int(b[p]); p += 1 }
            }
            guard p + len <= b.count else { return nil }
            return (p, p + len)
        }
        guard b.first == 0x30, let cert = tlv(0),
              cert.start < b.count, b[cert.start] == 0x30, let tbs = tlv(cert.start) else { return nil }
        var i = tbs.start
        if i < b.count, b[i] == 0xA0 {                       // [0] EXPLICIT version
            guard let v = tlv(i) else { return nil }; i = v.end
        }
        for _ in 0..<4 {                                      // serial, sigAlg, issuer, validity
            guard let e = tlv(i) else { return nil }; i = e.end
        }
        guard i < b.count, b[i] == 0x30, let subject = tlv(i) else { return nil }
        return Data(b[i..<subject.end])
    }

    // MARK: - TBSCertificate builders

    private static func tbs_CA(cn: String, publicKey: SecKey, validDays: Int) throws -> Data {
        let now      = Date()
        let notAfter = Calendar.current.date(byAdding: .day, value: validDays, to: now)!
        let spki     = try subjectPublicKeyInfo(publicKey)
        let bcExt    = derSequence(
            derOID(oidBasicConstraints) + derBoolean(true) +
            derOctetString(derSequence(derBoolean(true)))   // CA:TRUE
        )
        return derSequence(
            derExplicit(tag: 0xA0, derInteger(Data([0x02])))  // version v3
            + randomSerial()
            + algID()
            + rdnSequence(cn: cn)
            + validity(from: now, to: notAfter)
            + rdnSequence(cn: cn)
            + spki
            + derExplicit(tag: 0xA3, derSequence(bcExt))
        )
    }

    private static func tbs_Leaf(domain: String, publicKey: SecKey, issuer: Data) throws -> Data {
        // ±1 h clock skew tolerance
        let now      = Calendar.current.date(byAdding: .hour, value: -1, to: Date())!
        let notAfter = Calendar.current.date(byAdding: .hour, value: 25, to: now)!
        let spki     = try subjectPublicKeyInfo(publicKey)
        // SAN dNSName uses implicit context tag [2]
        let sanExt   = derSequence(
            derOID(oidSubjectAltName) +
            derOctetString(derSequence(derImplicit(tag: 0x82, Data(domain.utf8))))
        )
        // ExtendedKeyUsage { id-kp-serverAuth }. Apple's trust evaluator has
        // required an EKU containing serverAuth on every TLS server certificate
        // since iOS 13 / macOS 10.15 (regardless of which root anchors it);
        // without it the leaf is rejected with "Extended key usage does not
        // match certificate usage".
        let ekuExt   = derSequence(derOID(oidExtKeyUsage) + derOctetString(derSequence(derOID(oidServerAuth))))
        // BasicConstraints CA:FALSE (empty value sequence suffices)
        let bcExt    = derSequence(derOID(oidBasicConstraints) + derOctetString(derSequence(Data())))
        return derSequence(
            derExplicit(tag: 0xA0, derInteger(Data([0x02])))
            + randomSerial()
            + algID()
            + issuer
            + validity(from: now, to: notAfter)
            + rdnSequence(cn: domain)
            + spki
            + derExplicit(tag: 0xA3, derSequence(sanExt + ekuExt + bcExt))
        )
    }

    // MARK: - Assembly

    private static func assembleCert(tbs: Data, signingKey: SecKey) throws -> Data {
        var err: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(
            signingKey, .ecdsaSignatureMessageX962SHA256, tbs as CFData, &err
        ) as Data? else { throw err!.takeRetainedValue() as Error }
        return derSequence(tbs + algID() + derBitString(Data([0x00]) + sig))
    }

    // MARK: - DER primitives (internal visibility for tests)

    static func derLength(_ n: Int) -> Data {
        if n < 0x80 { return Data([UInt8(n)]) }
        var v = n; var b = [UInt8]()
        while v > 0 { b.insert(UInt8(v & 0xFF), at: 0); v >>= 8 }
        return Data([UInt8(0x80 | b.count)] + b)
    }

    static func derTLV(tag: UInt8, _ content: Data) -> Data {
        Data([tag]) + derLength(content.count) + content
    }

    static func derSequence(_ c: Data)     -> Data { derTLV(tag: 0x30, c) }
    static func derSet(_ c: Data)          -> Data { derTLV(tag: 0x31, c) }
    static func derOctetString(_ c: Data)  -> Data { derTLV(tag: 0x04, c) }
    static func derBitString(_ c: Data)    -> Data { derTLV(tag: 0x03, c) }
    static func derUTF8String(_ s: String) -> Data { derTLV(tag: 0x0C, Data(s.utf8)) }
    static func derBoolean(_ b: Bool)      -> Data { derTLV(tag: 0x01, Data([b ? 0xFF : 0x00])) }
    static func derOID(_ bytes: [UInt8])   -> Data { derTLV(tag: 0x06, Data(bytes)) }
    static func derExplicit(tag: UInt8, _ c: Data) -> Data { derTLV(tag: tag, c) }
    static func derImplicit(tag: UInt8, _ c: Data) -> Data { derTLV(tag: tag, c) }

    static func derInteger(_ bytes: Data) -> Data {
        var b = bytes
        while b.count > 1, b[b.startIndex] == 0x00,
              b[b.index(after: b.startIndex)] & 0x80 == 0 { b = b.dropFirst() }
        if let first = b.first, first & 0x80 != 0 { b = Data([0x00]) + b }
        return derTLV(tag: 0x02, b)
    }

    static func derUTCTime(_ date: Date) -> Data {
        let f = DateFormatter(); f.dateFormat = "yyMMddHHmmss'Z'"
        f.timeZone = TimeZone(identifier: "UTC")
        return derTLV(tag: 0x17, Data(f.string(from: date).utf8))
    }

    // MARK: - Helpers

    private static func algID() -> Data { derSequence(derOID(oidEcdsaSHA256)) }

    private static func rdnSequence(cn: String) -> Data {
        derSequence(derSet(derSequence(derOID(oidCommonName) + derUTF8String(cn))))
    }

    private static func validity(from: Date, to: Date) -> Data {
        derSequence(derUTCTime(from) + derUTCTime(to))
    }

    private static func randomSerial() -> Data {
        var b = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &b)
        b[0] &= 0x7F    // ensure positive integer
        return derInteger(Data(b))
    }

    private static func subjectPublicKeyInfo(_ key: SecKey) throws -> Data {
        var err: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(key, &err) as Data? else {
            throw err!.takeRetainedValue() as Error
        }
        // raw = X9.62 uncompressed point: 04 || x(32) || y(32)
        let algSeq = derSequence(derOID(oidECPublicKey) + derOID(oidPrime256v1))
        return derSequence(algSeq + derBitString(Data([0x00]) + raw))
    }
}

enum CertError: Error, LocalizedError {
    case cannotExtractPublicKey
    case invalidPEM
    case missingPrivateKey
    var errorDescription: String? {
        switch self {
        case .cannotExtractPublicKey: return "Cannot extract public key from private key"
        case .invalidPEM:            return "Invalid PEM - expected CERTIFICATE and PRIVATE KEY blocks"
        case .missingPrivateKey:     return "No private key found in the imported data"
        }
    }
}
