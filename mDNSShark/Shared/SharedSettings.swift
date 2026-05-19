// mDNSShark/Shared/SharedSettings.swift
// Add to both mDNSShark and PacketTunnel targets via Xcode Target Membership.
import Foundation
import os.log

enum SharedSettings {
    static let suiteName = "group.org.shapehaveninnovations.mDNSShark"
    static let suite: UserDefaults = {
        if let s = UserDefaults(suiteName: suiteName) { return s }
        os_log(.fault, "SharedSettings: App Group '%{public}@' unavailable - TLS inspection disabled", suiteName)
        return .standard
    }()

    private static let dropCountLock = NSLock()

    static var tlsInspectionEnabled: Bool {
        get { suite.bool(forKey: "tlsInspectionEnabled") }
        set { suite.set(newValue, forKey: "tlsInspectionEnabled") }
    }

    static var tlsBypassList: [String] {
        get {
            guard let data = suite.data(forKey: "tlsBypassList"),
                  let list = try? JSONDecoder().decode([String].self, from: data)
            else { return [] }
            return list
        }
        set {
            suite.set(try? JSONEncoder().encode(newValue), forKey: "tlsBypassList")
        }
    }

    static var dnsPrimary: String {
        get { suite.string(forKey: "dnsPrimary") ?? "8.8.8.8" }
        set { suite.set(newValue, forKey: "dnsPrimary") }
    }

    static var dnsSecondary: String {
        get { suite.string(forKey: "dnsSecondary") ?? "8.8.4.4" }
        set { suite.set(newValue, forKey: "dnsSecondary") }
    }

    // Default: all protocols enabled (empty data → all on)
    static var captureFilterProtocols: Set<String> {
        get {
            guard let data = suite.data(forKey: "captureFilterProtocols"),
                  let list = try? JSONDecoder().decode([String].self, from: data)
            else { return allProtocols }
            return Set(list)
        }
        set {
            suite.set(try? JSONEncoder().encode(Array(newValue)), forKey: "captureFilterProtocols")
        }
    }

    static let allProtocols: Set<String> = ["DNS", "mDNS", "HTTPS", "HTTP", "TCP", "UDP", "ICMP"]

    static var tlsInterceptorLastError: String {
        get { suite.string(forKey: "tlsInterceptorLastError") ?? "" }
        set { suite.set(newValue, forKey: "tlsInterceptorLastError") }
    }

    static var tlsInterceptorDropCount: Int {
        get { suite.integer(forKey: "tlsInterceptorDropCount") }
        set { suite.set(newValue, forKey: "tlsInterceptorDropCount") }
    }

    static func incrementDropCount() {
        dropCountLock.lock()
        suite.set(suite.integer(forKey: "tlsInterceptorDropCount") + 1, forKey: "tlsInterceptorDropCount")
        dropCountLock.unlock()
    }
}
