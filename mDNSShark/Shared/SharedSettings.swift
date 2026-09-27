// mDNSShark/Shared/SharedSettings.swift
// Add to both mDNSShark and PacketTunnel targets via Xcode Target Membership.
import Foundation
import os.log

enum SharedSettings {
    static let suiteName = "group.beta.mDNSShark"
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

    // Set by PurchaseManager (main app process) whenever it refreshes StoreKit
    // entitlements. The PacketTunnel extension reads this instead of talking to
    // StoreKit itself, since it has no purchase UI of its own.
    static var tlsInspectionUnlocked: Bool {
        get { suite.bool(forKey: "tlsInspectionUnlocked") }
        set { suite.set(newValue, forKey: "tlsInspectionUnlocked") }
    }

    // Cached alongside tlsInspectionUnlocked so PurchaseManager can seed an accurate
    // TrialState (with days-remaining) on launch, before Transaction.currentEntitlements resolves.
    static var tlsTrialStartDate: Date? {
        get { suite.object(forKey: "tlsTrialStartDate") as? Date }
        set { suite.set(newValue, forKey: "tlsTrialStartDate") }
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

    /// Off by default — matches the tunnel's existing, unexamined behavior
    /// exactly (`includeAllNetworks` was previously just never set). Read by
    /// `PacketCaptureManager.configureVPN` (app side, at Start Capture time —
    /// NOT inside the `PacketTunnelProvider` extension) to set
    /// `includeAllNetworks` on the saved `NETunnelProviderProtocol`/
    /// `NEVPNProtocol` config, which per Apple/DTS is likely required to
    /// route same-subnet LAN traffic through the tunnel at all (todo.md item
    /// 1) — but doing so also puts every LAN packet, not just scan probes,
    /// through `PacketForwarder`'s relay path, which is the other open
    /// question in that item (added relay latency vs. the scanner's short
    /// probe timeouts). Exists so dev can flip it from Settings to run the
    /// capture-on/capture-off on-device A/B test item 1 calls for, without a
    /// code change — stop capture, toggle, start capture again (only takes
    /// effect on the next `startCapture()`, since it's read when the VPN
    /// config is saved, not while the tunnel is already running).
    static var includeAllNetworksInCapture: Bool {
        get { suite.bool(forKey: "includeAllNetworksInCapture") }
        set { suite.set(newValue, forKey: "includeAllNetworksInCapture") }
    }

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
