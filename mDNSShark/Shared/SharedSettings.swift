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

    // Subscription expiry mirrored by PurchaseManager (main app process) from StoreKit.
    // The PacketTunnel extension has no StoreKit access of its own, so it reads this.
    static var tlsSubscriptionExpiry: Date? {
        get { suite.object(forKey: "tlsSubscriptionExpiry") as? Date }
        set { suite.set(newValue, forKey: "tlsSubscriptionExpiry") }
    }

    // Recomputed on every read so the extension enforces expiry without waiting
    // for the main app to republish.
    static var tlsAccessGranted: Bool {
        guard let expiry = tlsSubscriptionExpiry else { return false }
        return expiry > Date()
    }

    // Apple's own account-scoped answer to "has this Apple ID ever obtained
    // this app before" (AppTransaction.appTransactionID), cached so
    // PurchaseManager.reconcileOwnership() can tell a genuine relaunch under
    // the same account apart from a restored backup, a fresh install that
    // inherited leftover App Group state, or a switch to a different Apple
    // ID - none of which this App Group UserDefaults suite is scoped to on
    // its own. A mismatch means tlsSubscriptionExpiry on disk belongs to a
    // different account and must not be trusted.
    static var ownerAppTransactionID: String? {
        get { suite.string(forKey: "ownerAppTransactionID") }
        set { suite.set(newValue, forKey: "ownerAppTransactionID") }
    }

    /// Domains that always fail TLS Inspection by design, not by bug, so
    /// they're bypassed by default until the user sets their own list. Apple
    /// Private Relay's egress rejects any TLS-inspecting proxy outright
    /// (upstream connect fails with -9830 illegal parameter), silently
    /// breaking Private Relay instead of just showing a diagnostic.
    static let defaultTLSBypassDomains: [String] = ["mask.icloud.com", "mask-h2.icloud.com"]

    static var tlsBypassList: [String] {
        get {
            guard let data = suite.data(forKey: "tlsBypassList"),
                  let list = try? JSONDecoder().decode([String].self, from: data)
            else { return Self.defaultTLSBypassDomains }
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

    /// Resolvers handed to the tunnel: trimmed, deduped, valid IPv4 literals only, falling back to
    /// Google DNS when nothing usable is saved so a typo can't stop the tunnel from starting.
    static var dnsServers: [String] {
        var seen = Set<String>()
        let valid = [dnsPrimary, dnsSecondary]
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { addr in
                // IPv4 only: the tunnel has no IPv6 settings or routes and PacketForwarder drops non-IPv4.
                var v4 = in_addr()
                return inet_pton(AF_INET, addr, &v4) == 1 && seen.insert(addr).inserted
            }
        return valid.isEmpty ? ["8.8.8.8", "8.8.4.4"] : valid
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

    /// True when a raw TLSInterceptor drop reason describes a benign,
    /// expected condition (nothing was listening on the real destination)
    /// rather than something worth surfacing to the user (a certificate/
    /// identity failure, an unexpected mid-session reset, or a genuine
    /// internal bridge problem). The full raw string is still always kept
    /// here for Settings; this only decides whether ContentView's Topology
    /// banner also shows it. Real example that motivated this: "Upstream to
    /// 192.168.8.243:443 ... never became ready within 10s (...
    /// POSIXErrorCode(rawValue: 61): Connection refused ...)" fires simply
    /// because that host isn't running an HTTPS server on 443, a normal,
    /// constant background condition on any LAN scan, not a security
    /// finding.
    ///
    /// Excludes any reason mentioning the loopback bridge (127.0.0.1): a
    /// refusal there means our own local listener broke, which is a real
    /// internal bug and can carry the same "Connection refused" text as the
    /// benign upstream-refusal case.
    static func isBenignTLSDropReason(_ reason: String) -> Bool {
        guard !reason.isEmpty else { return true }
        let refused = reason.contains("Connection refused")
            || reason.contains("POSIXErrorCode(rawValue: 61)")
            || reason.contains("errno=61")
        guard refused else { return false }
        return !reason.contains("127.0.0.1")
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
