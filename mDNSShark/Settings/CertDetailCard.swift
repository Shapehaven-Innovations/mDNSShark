// mDNSShark/Settings/CertDetailCard.swift
import SwiftUI
import UIKit
import CryptoKit

struct CertDetailCard: View {
    let cert: SecCertificate

    private var subject: String   { extractCN() ?? "Unknown" }
    private var expiry: Date?     { extractExpiry() }
    private var fingerprint: String { sha256Fingerprint() }
    private var isExpiringSoon: Bool {
        guard let d = expiry else { return false }
        return d.timeIntervalSinceNow < 30 * 86400
    }

    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            LabeledContent("Subject", value: subject)
            if let d = expiry {
                LabeledContent("Expires") {
                    Text(d, style: .date)
                        .foregroundColor(isExpiringSoon ? .red : .primary)
                }
            }
            HStack {
                LabeledContent("Fingerprint", value: String(fingerprint.prefix(32)) + "…")
                Spacer()
                Button(copied ? "Copied" : "Copy") {
                    UIPasteboard.general.string = fingerprint
                    copied = true
                    Task { try? await Task.sleep(nanoseconds: 2_000_000_000); copied = false }
                }
                .font(.caption)
                .buttonStyle(.borderless)
            }
        }
        .font(.subheadline)
    }

    // MARK: - Certificate data extraction

    private func extractCN() -> String? {
        var cn: CFString?
        guard SecCertificateCopyCommonName(cert, &cn) == errSecSuccess else { return nil }
        return cn as String?
    }

    // Walk the X.509 DER to find NotAfter in the Validity SEQUENCE.
    private func extractExpiry() -> Date? {
        let der = [UInt8](SecCertificateCopyData(cert) as Data)
        var i = 0
        guard derEnter(der, at: &i) else { return nil }           // Certificate SEQUENCE
        guard derEnter(der, at: &i) else { return nil }           // TBSCertificate SEQUENCE
        if i < der.count && der[i] == 0xA0 { derSkip(der, at: &i) } // version [0] (optional)
        derSkip(der, at: &i)                                       // serialNumber
        derSkip(der, at: &i)                                       // signature AlgorithmIdentifier
        derSkip(der, at: &i)                                       // issuer
        guard derEnter(der, at: &i) else { return nil }           // Validity SEQUENCE
        derSkip(der, at: &i)                                       // notBefore - skip
        return derReadTime(der, at: &i)                            // notAfter
    }

    private func sha256Fingerprint() -> String {
        let data = SecCertificateCopyData(cert) as Data
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - DER helpers

    private func derReadLength(_ bytes: [UInt8], at i: Int) -> (length: Int, advance: Int) {
        guard i < bytes.count else { return (0, 0) }
        let first = Int(bytes[i])
        if first < 0x80 { return (first, 1) }
        let numBytes = first & 0x7F
        guard i + numBytes < bytes.count else { return (0, 0) }
        var len = 0
        for j in 1...numBytes { len = (len << 8) | Int(bytes[i + j]) }
        return (len, 1 + numBytes)
    }

    // Verify tag matches, then advance i past the tag+length header into the element's content.
    @discardableResult
    private func derEnter(_ bytes: [UInt8], at i: inout Int, tag: UInt8 = 0x30) -> Bool {
        guard i < bytes.count, bytes[i] == tag else { return false }
        i += 1
        let (_, advance) = derReadLength(bytes, at: i)
        i += advance
        return true
    }

    // Skip one complete DER element (tag + length + content).
    private func derSkip(_ bytes: [UInt8], at i: inout Int) {
        guard i < bytes.count else { return }
        i += 1
        let (len, advance) = derReadLength(bytes, at: i)
        i += advance + len
    }

    // Read a UTCTime (0x17) or GeneralizedTime (0x18) element and return a Date.
    private func derReadTime(_ bytes: [UInt8], at i: inout Int) -> Date? {
        guard i < bytes.count else { return nil }
        let tag = bytes[i]
        guard tag == 0x17 || tag == 0x18 else { return nil }
        i += 1
        let (len, advance) = derReadLength(bytes, at: i)
        i += advance
        guard i + len <= bytes.count else { return nil }
        let str = String(bytes: Array(bytes[i..<i+len]), encoding: .ascii) ?? ""
        i += len
        let fmt = DateFormatter()
        fmt.locale = Locale(identifier: "en_US_POSIX")
        fmt.timeZone = TimeZone(identifier: "UTC")
        fmt.dateFormat = tag == 0x17 ? "yyMMddHHmmss'Z'" : "yyyyMMddHHmmss'Z'"
        return fmt.date(from: str)
    }
}
