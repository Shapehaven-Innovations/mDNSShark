// mDNSShark/Shared/KeychainStore.swift
// Add to both mDNSShark and PacketTunnel targets via Xcode Target Membership.
import Security
import Foundation

enum KeychainStore {
    static let accessGroup = "group.org.shapehaveninnovations.mDNSShark"
    private static let certLabel = "mDNSShark.caCert"
    private static let keyLabel  = "mDNSShark.caKey"

    // MARK: - CA Certificate

    static func saveCACert(_ cert: SecCertificate) throws {
        deleteCACert()
        let attrs: [String: Any] = [
            kSecClass as String:           kSecClassCertificate,
            kSecValueRef as String:        cert,
            kSecAttrLabel as String:       certLabel,
            kSecAttrAccessGroup as String: accessGroup
        ]
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.status(status) }
    }

    static func loadCACert() -> SecCertificate? {
        let query: [String: Any] = [
            kSecClass as String:           kSecClassCertificate,
            kSecAttrLabel as String:       certLabel,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnRef as String:       true
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        // CF types always bridge to their exact type when kSecReturnRef succeeds
        return (result as! SecCertificate)
    }

    static func deleteCACert() {
        let query: [String: Any] = [
            kSecClass as String:           kSecClassCertificate,
            kSecAttrLabel as String:       certLabel,
            kSecAttrAccessGroup as String: accessGroup
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - CA Private Key

    static func saveCAKey(_ key: SecKey) throws {
        deleteCAKey()
        let attrs: [String: Any] = [
            kSecClass as String:           kSecClassKey,
            kSecValueRef as String:        key,
            kSecAttrLabel as String:       keyLabel,
            kSecAttrAccessGroup as String: accessGroup
        ]
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.status(status) }
    }

    static func loadCAKey() -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String:           kSecClassKey,
            kSecAttrLabel as String:       keyLabel,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrKeyClass as String:    kSecAttrKeyClassPrivate,
            kSecReturnRef as String:       true
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return (result as! SecKey)
    }

    static func deleteCAKey() {
        let query: [String: Any] = [
            kSecClass as String:           kSecClassKey,
            kSecAttrLabel as String:       keyLabel,
            kSecAttrAccessGroup as String: accessGroup
        ]
        SecItemDelete(query as CFDictionary)
    }

    static func deleteCAItems() { deleteCACert(); deleteCAKey() }

    // MARK: - Leaf cert/key helpers (used by TLSInterceptor for per-domain certs)

    static func saveLeafKey(_ key: SecKey, domain: String) throws {
        let tag = leafTag(domain)
        let attrs: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecValueRef as String:           key,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessGroup as String:    accessGroup
        ]
        SecItemDelete([
            kSecClass as String:              kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessGroup as String:    accessGroup
        ] as CFDictionary)
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.status(status) }
    }

    static func saveLeafCert(_ cert: SecCertificate, domain: String) throws {
        let lbl = leafLabel(domain)
        SecItemDelete([
            kSecClass as String:           kSecClassCertificate,
            kSecAttrLabel as String:       lbl,
            kSecAttrAccessGroup as String: accessGroup
        ] as CFDictionary)
        let attrs: [String: Any] = [
            kSecClass as String:           kSecClassCertificate,
            kSecValueRef as String:        cert,
            kSecAttrLabel as String:       lbl,
            kSecAttrAccessGroup as String: accessGroup
        ]
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.status(status) }
    }

    static func loadLeafIdentity(domain: String) -> SecIdentity? {
        // Step 1: load the cert by its label (reliable - we set this explicitly).
        let certQuery: [String: Any] = [
            kSecClass as String:           kSecClassCertificate,
            kSecAttrLabel as String:       leafLabel(domain),
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnRef as String:       true
        ]
        var certResult: CFTypeRef?
        guard SecItemCopyMatching(certQuery as CFDictionary, &certResult) == errSecSuccess,
              certResult != nil else { return nil }
        let cert = certResult as! SecCertificate

        // Step 2: resolve the identity that pairs this cert with its private key.
        // kSecMatchItemList is more reliable than label-matching kSecClassIdentity on iOS.
        let idQuery: [String: Any] = [
            kSecClass as String:           kSecClassIdentity,
            kSecMatchItemList as String:   [cert] as CFArray,
            kSecAttrAccessGroup as String: accessGroup,
            kSecReturnRef as String:       true
        ]
        var idResult: CFTypeRef?
        guard SecItemCopyMatching(idQuery as CFDictionary, &idResult) == errSecSuccess else { return nil }
        return (idResult as! SecIdentity)
    }

    static func deleteLeafItems(domain: String) {
        let lbl = leafLabel(domain)
        let tag = leafTag(domain)
        SecItemDelete([kSecClass as String: kSecClassCertificate,
                       kSecAttrLabel as String: lbl,
                       kSecAttrAccessGroup as String: accessGroup] as CFDictionary)
        SecItemDelete([kSecClass as String: kSecClassKey,
                       kSecAttrApplicationTag as String: tag,
                       kSecAttrAccessGroup as String: accessGroup] as CFDictionary)
    }

    static func deleteAllLeafItems(domains: [String]) {
        for domain in domains {
            deleteLeafItems(domain: domain)
        }
    }

    private static func leafLabel(_ domain: String) -> String { "mdns.leaf.\(domain)" }
    private static func leafTag(_ domain: String) -> Data { Data("mdns.leaf.\(domain)".utf8) }
}

enum KeychainError: Error, LocalizedError {
    case status(OSStatus)
    var errorDescription: String? {
        switch self {
        case .status(let s): return "Keychain error (OSStatus \(s)). Check App Group entitlements."
        }
    }
}
