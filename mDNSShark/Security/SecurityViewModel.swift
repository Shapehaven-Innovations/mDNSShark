// mDNSShark/Security/SecurityViewModel.swift
import Foundation
import Combine
import os

enum GroupMode: String, CaseIterable {
    case severity = "Severity"
    case device   = "Device"
    case all      = "All"
}

/// User-facing reason a threat-data refresh didn't succeed. Distinct from
/// `ThreatRefreshError` (the actor's internal error) so the UI only has to
/// handle the handful of cases it actually shows different copy for.
enum ThreatRefreshFailure: Equatable {
    case captureActive
    case cancelledByCapture
    case network
    case unusableData
    case saveFailed
}

@MainActor
final class SecurityViewModel: ObservableObject {
    @Published var findings:     [SecurityFinding] = []
    @Published var isAssessing:  Bool = false
    @Published private(set) var isRefreshing: Bool = false
    @Published private(set) var threatDataStatus: ThreatDataStatus?
    @Published private(set) var refreshError: ThreatRefreshFailure?
    /// When the last refresh finished both its KEV and NVD phases.
    @Published private(set) var lastRefreshCompletedAt: Date?
    @Published var groupMode:    GroupMode = .severity

    private let threatDatabase: ThreatDatabase
    private let isTunnelActive: @Sendable () async -> Bool
    private var refreshTask: Task<Void, Never>?
    private var lastAssessedDevices: [DiscoveredDevice] = []
    private let logger = Logger(subsystem: "com.mDNSShark", category: "SecurityViewModel")

    /// Identifies the most recently STARTED `assess()` call. `$devices`
    /// publishes constantly mid-scan (every enrichment result updates it),
    /// and `AppCoordinator` spawns an independent, uncancelled `Task` per
    /// publish. With no ordering guarantee between them, an early call
    /// (snapshotted before a device's open ports were known) can finish
    /// AFTER a later, fully-enriched call and silently overwrite `findings`
    /// with a stale, incomplete result. `assess()` checks this token before
    /// committing its result, discarding itself if a newer call has since
    /// started rather than clobbering that newer call's (possibly
    /// still-in-flight) result.
    private var currentAssessmentID = UUID()

    // MARK: - Rules

    private let portRules: [Int: (Severity, String, String, String)] = [
        // Only cleartext-credential ports are critical; nothing here checks versions, so every other rule caps at .warning.
        23:   (.critical,     "Telnet Exposed",            "Exposed Telnet service. Telnet sends logins and passwords in cleartext.",                    "Disable Telnet. Use SSH instead."),
        21:   (.critical,     "FTP Exposed",               "Exposed FTP service. FTP sends logins and passwords in cleartext.",                          "Disable FTP. Use SFTP/SCP instead."),
        5900: (.warning,      "VNC Exposed",               "Exposed VNC remote desktop service on the local network.",                                   "Disable VNC or restrict to trusted IPs."),
        5800: (.warning,      "VNC Web Interface Exposed", "Exposed VNC web console on the local network.",                                              "Disable VNC web interface."),
        3389: (.warning,      "RDP Exposed",               "Exposed Remote Desktop service. RDP is a common brute-force target.",                        "Disable RDP or restrict to VPN only."),
        445:  (.warning,      "SMB Exposed",               "Exposed SMB file sharing service on the local network.",                                     "Keep SMB patched. Disable if unused."),
        139:  (.warning,      "NetBIOS Exposed",           "NetBIOS session service exposed.",                                                           "Disable NetBIOS over TCP/IP if unused."),
        22:   (.warning,      "SSH Exposed",               "SSH provides remote shell access. Ensure password auth is disabled.",                        "Use key-based SSH auth. Disable root login."),
        554:  (.warning,      "RTSP Stream Exposed",       "RTSP may allow unauthorized access to camera or media streams.",                             "Restrict RTSP to trusted IPs."),
        1900: (.informational,"UPnP Exposed",              "UPnP can be abused to open router ports without authorization.",                             "Disable UPnP on your router if unused."),
        80:   (.informational,"HTTP Service",              "Unencrypted HTTP service. Traffic is readable on the local network.",                        "Prefer HTTPS."),
        8080: (.informational,"HTTP Alternate Port",       "HTTP service on port 8080.",                                                                 "Confirm this is an intended service."),
        443:  (.informational,"HTTPS Admin Interface",     "An encrypted web admin interface is exposed on the local network.",                          "Confirm this is an intended service and uses a strong password."),
        8443: (.informational,"HTTPS Alternate Port",      "HTTPS service on port 8443.",                                                                 "Confirm this is an intended service.")
    ]

    // All informational: an advertisement says a service may be running, not that its port is open.
    private let bonjourRules: [String: (Severity, String, String, String)] = [
        "_telnet._tcp":           (.informational,"Telnet Advertised via Bonjour",  "A Telnet service is advertised. Telnet sends logins and passwords in cleartext.",   "Disable Telnet if unused. Use SSH instead."),
        "_rfb._tcp":              (.informational,"VNC Advertised via Bonjour",     "A VNC remote desktop service is advertised.",                                        "Disable VNC or restrict to trusted hosts."),
        "_vnc._tcp":              (.informational,"VNC Advertised via Bonjour",     "A VNC remote desktop service is advertised.",                                        "Disable VNC or restrict to trusted hosts."),
        "_ftp._tcp":              (.informational,"FTP Advertised via Bonjour",     "An FTP service is advertised. FTP sends logins and passwords in cleartext.",         "Disable FTP if unused. Use SFTP instead."),
        "_remotemanagement._tcp": (.informational,"Remote Management Advertised",   "Apple Remote Desktop management is advertised on the network.",                      "Restrict Remote Management to authorized users."),
        "_ssh._tcp":              (.informational,"SSH Advertised via Bonjour",     "An SSH remote access service is advertised.",                                        "Use key-based auth. Disable root login."),
        "_smb._tcp":              (.informational,"SMB File Sharing Advertised",    "A Windows-compatible file sharing service is advertised.",                           "Keep SMB patched. Restrict shares."),
        "_workstation._tcp":      (.informational,"SMB Workstation Advertised",     "A workstation SMB service is advertised.",                                           "Ensure SMB shares require authentication."),
        "_http._tcp":             (.informational,"HTTP Service Advertised",        "Unencrypted web service detected.",                                                  "Prefer HTTPS."),
        "_airplay._tcp":          (.informational,"AirPlay Receiver Advertised",    "This device accepts AirPlay streams from other devices on the network.",             "Limit AirPlay to the current user or turn it off when unused."),
        "_raop._tcp":             (.informational,"AirPlay Receiver Advertised",    "This device accepts AirPlay streams from other devices on the network.",             "Limit AirPlay to the current user or turn it off when unused."),
        "_hap._tcp":              (.informational,"HomeKit Accessory Present",      "A HomeKit device is on your network.",                                               "Ensure HomeKit uses a secure home hub."),
        "_printer._tcp":          (.informational,"Network Printer Discovered",     "A network printer is available.",                                                    "Keep printer firmware up to date."),
        "_ipp._tcp":              (.informational,"IPP Printer Discovered",         "An IPP-capable printer is discoverable.",                                            "Keep printer firmware up to date.")
    ]

    // MARK: - Init

    init(threatDatabase: ThreatDatabase, isTunnelActive: @escaping @Sendable () async -> Bool) {
        self.threatDatabase = threatDatabase
        self.isTunnelActive = isTunnelActive
    }

    // MARK: - Public API

    /// `showProgress: false` is for refresh-triggered re-assessment, which updates findings in place without the "Assessing" bar.
    func assess(devices: [DiscoveredDevice], showProgress: Bool = true) async {
        lastAssessedDevices = devices
        let assessmentID = UUID()
        currentAssessmentID = assessmentID
        if showProgress { isAssessing = true }
        var all: [SecurityFinding] = []
        for device in devices {
            async let pf = portFindings(device: device)
            async let bf = bonjourFindings(device: device)
            async let tf = threatFindings(device: device)
            all += await pf + bf + tf
        }
        // A newer call already superseded this one while the awaits above
        // were in flight - discard this stale result instead of
        // overwriting whatever the newer call already committed (or is
        // still computing).
        guard currentAssessmentID == assessmentID else { return }
        var seen = Set<String>()
        let deduped = all.filter { f in seen.insert(findingKey(f)).inserted }
        // Reuse existing IDs so unchanged rows keep their identity, and skip publishing an identical result.
        let existingIDs = Dictionary(findings.map { (findingKey($0), $0.id) }, uniquingKeysWith: { first, _ in first })
        let updated = deduped.map { f in existingIDs[findingKey(f)].map { f.withID($0) } ?? f }
        if updated != findings { findings = updated }
        // Also clears a superseded progress-showing call's bar, which returned early without resetting it.
        if isAssessing { isAssessing = false }
    }

    private func findingKey(_ f: SecurityFinding) -> String { "\(f.deviceID)-\(f.title)" }

    /// Loads the current threat-data status (bundled snapshot date, last
    /// successful refresh if any) without fetching anything. Called once
    /// at launch so the status line has real data before the user ever
    /// taps refresh.
    func loadThreatDataStatus() async {
        threatDataStatus = await threatDatabase.status()
    }

    /// Starts a refresh if one isn't already running. Synchronous and
    /// MainActor-isolated, so a double tap is caught here before it ever
    /// reaches the actor's own (defense-in-depth) `.alreadyRefreshing`
    /// guard.
    func startThreatDataRefresh() {
        guard !isRefreshing else { return }
        isRefreshing = true
        refreshError = nil
        refreshTask = Task { [weak self] in
            await self?.performThreatDataRefresh()
        }
    }

    /// Cancels an in-flight refresh. Called when LAN capture starts, since
    /// a refresh's request to cisa.gov would otherwise get routed into the
    /// capture tunnel (and MITM'd by TLSInterceptor, if active) — see the
    /// `isTunnelActive` pre-flight check in `performThreatDataRefresh`.
    func cancelThreatDataRefresh() {
        refreshTask?.cancel()
    }

    /// Runs the KEV phase to completion (committing and re-assessing on
    /// success) before starting the NVD phase, so a slow/flaky NVD fetch
    /// never delays the already-fast KEV update. The two phases are
    /// otherwise independent: an NVD failure never rolls back a successful
    /// KEV refresh, and vice versa - `refreshError` reflects whichever
    /// phase actually failed, preferring to surface a KEV-phase failure
    /// since that's the phase the user is more likely waiting on.
    private func performThreatDataRefresh() async {
        defer {
            isRefreshing = false
            refreshTask = nil
        }

        if await isTunnelActive() {
            refreshError = .captureActive
            return
        }

        // Stamped only when both phases finish, not on .alreadyRefreshing or a logged NVD failure.
        var kevCompleted = false
        var nvdCompleted = false
        do {
            let status = try await threatDatabase.refresh()
            kevCompleted = true
            threatDataStatus = status
            if !lastAssessedDevices.isEmpty {
                await assess(devices: lastAssessedDevices, showProgress: false)
            }
        } catch let error as ThreatRefreshError {
            switch error {
            case .alreadyRefreshing:
                break
            case .cancelled:
                refreshError = .cancelledByCapture
            case .network:
                refreshError = .network
            case .badStatus, .undecodable, .implausibleFeed:
                refreshError = .unusableData
            case .persistence:
                refreshError = .saveFailed
            }
        } catch {
            refreshError = .network
        }

        do {
            let priorityManufacturers = lastAssessedDevices.compactMap(\.manufacturer)
            try await threatDatabase.refreshNVDVendorData(priorityManufacturers: priorityManufacturers)
            nvdCompleted = true
            threatDataStatus = await threatDatabase.status()
            if !lastAssessedDevices.isEmpty {
                await assess(devices: lastAssessedDevices, showProgress: false)
            }
        } catch ThreatRefreshError.cancelled {
            if refreshError == nil { refreshError = .cancelledByCapture }
        } catch is CancellationError {
            if refreshError == nil { refreshError = .cancelledByCapture }
        } catch {
            logger.error("NVD vendor refresh failed: \(String(describing: error), privacy: .public)")
        }
        if kevCompleted && nvdCompleted { lastRefreshCompletedAt = Date() }
    }

    // MARK: - Computed views of findings

    var criticalFindings: [SecurityFinding]      { findings.filter { $0.severity == .critical      } }
    var warningFindings:  [SecurityFinding]      { findings.filter { $0.severity == .warning       } }
    var informationalFindings: [SecurityFinding] { findings.filter { $0.severity == .informational } }

    /// Devices with a warning or critical finding about the device itself. Excludes `.vendorAdvisory` (a
    /// vendor-name match is not a confirmed vulnerability on this device) and informational findings.
    var vulnerableDeviceIDs: Set<UUID> {
        Set(findings.filter { $0.source != .vendorAdvisory && $0.severity >= .warning }.map { $0.deviceID })
    }

    var vulnerableDeviceCount: Int { vulnerableDeviceIDs.count }

    var allFindingsSorted: [SecurityFinding] {
        findings.sorted { $0.severity > $1.severity }
    }

    var findingsByDevice: [(deviceName: String, deviceIcon: String, findings: [SecurityFinding])] {
        var dict: [String: [SecurityFinding]] = [:]
        for f in findings { dict[f.deviceName, default: []].append(f) }
        return dict
            .map { name, group -> (String, String, [SecurityFinding]) in
                let icon = group.first?.deviceIcon ?? "questionmark.circle"
                let sorted = group.sorted { $0.severity > $1.severity }
                return (name, icon, sorted)
            }
            .sorted { $0.0 < $1.0 }
    }

    var exportText: String {
        let df = DateFormatter()
        df.dateStyle = .medium
        df.timeStyle = .short
        var lines = [
            "mDNSShark Security Report",
            "Generated: \(df.string(from: Date()))",
            "\(threatDataStatus?.summary().text ?? "CISA exploit data: not yet loaded.")",
            "Findings flag exposed services and manufacturers with published advisories; a match does not confirm a specific vulnerability is present on a device. Manufacturer checked live against \(threatDataStatus?.vendorCount ?? 0) vendors' CISA KEV entries and \(threatDataStatus?.nvdVendorCount ?? 0) vendors' NVD entries.",
            "",
            "=== SUMMARY ===",
            "Total findings: \(findings.count)  |  Vulnerable devices: \(vulnerableDeviceCount)",
            "Critical: \(criticalFindings.count)  |  Warning: \(warningFindings.count)  |  Informational: \(informationalFindings.count)",
            "",
            "=== FINDINGS ==="
        ]
        for (deviceName, _, deviceFindings) in findingsByDevice {
            lines.append("")
            lines.append("[\(deviceName)]")
            for f in deviceFindings {
                lines.append("  [\(f.severity.exportLabel)] \(f.title)")
                lines.append("  \(f.description)")
                for tier in f.cveTiers {
                    lines.append("  \(tier.label): \(tier.cveIDs.joined(separator: ", "))")
                }
                lines.append("  Recommendation: \(f.recommendation)")
                if let cve = f.cveID, let url = f.referenceURL {
                    lines.append("  Reference: \(cve) - \(url.absoluteString)")
                }
            }
        }
        lines += [
            "",
            "Generated by mDNSShark on this device. Scan results are not uploaded anywhere.",
            "This product uses the NVD API but is not endorsed or certified by the NVD."
        ]
        return lines.joined(separator: "\n")
    }

    // MARK: - Private assessment layers

    private func portFindings(device: DiscoveredDevice) async -> [SecurityFinding] {
        let name = "\(device.hostname) · \(device.ipAddress)"
        let icon = device.deviceIcon
        return device.openPorts.compactMap { port -> SecurityFinding? in
            guard let (sev, title, desc, rec) = portRules[port] else { return nil }
            return SecurityFinding(
                deviceID: device.id, deviceName: name, deviceIcon: icon,
                severity: sev, title: title, description: desc,
                recommendation: rec, source: .portRule
            )
        }
    }

    private func bonjourFindings(device: DiscoveredDevice) async -> [SecurityFinding] {
        let name = "\(device.hostname) · \(device.ipAddress)"
        let icon = device.deviceIcon
        return device.bonjourServices.compactMap { svc -> SecurityFinding? in
            guard let (sev, title, desc, rec) = bonjourRules[svc.serviceType] else { return nil }
            return SecurityFinding(
                deviceID: device.id, deviceName: name, deviceIcon: icon,
                severity: sev, title: title, description: desc,
                recommendation: rec, source: .bonjourRule
            )
        }
    }

    /// The only per-device CVE source: a manufacturer-name match against
    /// live KEV/NVD data (`vendorAdvisoryFinding`). There used to also be a
    /// per-Bonjour-service lookup against a static 5-CVE map
    /// (`_telnet._tcp`/`_rfb._tcp`/`_vnc._tcp`/`_ftp._tcp`) that stamped
    /// every match `.critical` regardless of which server was actually
    /// running - e.g. any `_ftp._tcp` device got flagged for the vsftpd
    /// 2.3.4 backdoor whether or not it ran vsftpd at all - duplicating the
    /// `bonjourRules` exposure finding that already correctly flags "FTP
    /// exposed" for the same device. Removed rather than fixed in place:
    /// nothing here can confirm which server software a device runs without
    /// the banner-capture work tracked as a separate follow-up.
    private func threatFindings(device: DiscoveredDevice) async -> [SecurityFinding] {
        let name = "\(device.hostname) · \(device.ipAddress)"
        let icon = device.deviceIcon
        var results: [SecurityFinding] = []
        if let advisory = await vendorAdvisoryFinding(device: device, name: name, icon: icon) {
            results.append(advisory)
        }
        return results
    }

    /// One grouped finding per device per vendor - never one per CVE - since
    /// a manufacturer-name match only means "this vendor has actively
    /// exploited (KEV) or otherwise known (NVD) vulnerabilities somewhere in
    /// its line," not that this specific device runs the affected
    /// model/firmware. Group severity is the max across matches: any KEV
    /// match or NVD CRITICAL/HIGH match makes the group `.warning`; if only
    /// NVD MEDIUM matches exist, `.informational`. Never `.critical`, and
    /// always excluded from `vulnerableDeviceCount` - the source-level
    /// tiering is otherwise invisible once grouped, so the description
    /// spells out the breakdown explicitly.
    private func vendorAdvisoryFinding(device: DiscoveredDevice, name: String, icon: String) async -> SecurityFinding? {
        let matches = await threatDatabase.vendorAdvisory(manufacturer: device.manufacturer)
        guard !matches.isEmpty else { return nil }
        let vendorName = matches[0].vendorDisplayName

        let kevMatches = matches.filter { $0.source == .kev }
        let nvdHighMatches = matches.filter {
            $0.source == .nvd && ["CRITICAL", "HIGH"].contains($0.cvssBaseSeverity?.uppercased() ?? "")
        }
        let nvdMediumMatches = matches.filter {
            $0.source == .nvd && $0.cvssBaseSeverity?.uppercased() == "MEDIUM"
        }
        let severity: Severity = (!kevMatches.isEmpty || !nvdHighMatches.isEmpty) ? .warning : .informational

        func entries(_ vendorFindings: [VendorFinding]) -> [CVETierEntry] {
            vendorFindings.map { CVETierEntry(cveID: $0.cveID, title: $0.title) }
        }
        var cveTiers: [CVETier] = []
        if !kevMatches.isEmpty {
            cveTiers.append(CVETier(label: "\(kevMatches.count) KEV", severity: .critical, entries: entries(kevMatches)))
        }
        if !nvdHighMatches.isEmpty {
            cveTiers.append(CVETier(label: "\(nvdHighMatches.count) High/Crit", severity: .warning, entries: entries(nvdHighMatches)))
        }
        if !nvdMediumMatches.isEmpty {
            cveTiers.append(CVETier(label: "\(nvdMediumMatches.count) Medium", severity: .informational, entries: entries(nvdMediumMatches)))
        }

        let plural = matches.count == 1 ? "vulnerability" : "vulnerabilities"
        let queryValueAllowed = CharacterSet.urlQueryAllowed.subtracting(CharacterSet(charactersIn: "&+=?#"))
        let encodedVendorName = vendorName.addingPercentEncoding(withAllowedCharacters: queryValueAllowed) ?? vendorName
        let referenceURL = kevMatches.isEmpty
            ? URL(string: "https://nvd.nist.gov/vuln/search/results?query=\(encodedVendorName)")
            : URL(string: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=\(encodedVendorName)")

        return SecurityFinding(
            deviceID: device.id, deviceName: name, deviceIcon: icon,
            severity: severity,
            title: "\(vendorName): known \(plural)",
            description: "This device's manufacturer (\(vendorName)) has \(matches.count) known \(plural). This flags the vendor, not a confirmed issue on this specific device.",
            recommendation: "Check this device's exact model and firmware version against \(vendorName)'s published security advisories, and update if a patch is available.",
            source: .vendorAdvisory,
            cveID: nil,
            referenceURL: referenceURL,
            cveTiers: cveTiers
        )
    }
}
