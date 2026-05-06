// mDNSShark/Security/SecurityViewModel.swift
import Foundation
import Combine
import os

@MainActor
final class SecurityViewModel: ObservableObject {
    @Published var findings: [SecurityFinding] = []
    @Published var isAssessing: Bool = false
    @Published var isRefreshing: Bool = false
    @Published var lastRefreshDate: Date? = nil

    private let threatDatabase: ThreatDatabase
    private let logger = Logger(subsystem: "com.mDNSShark", category: "SecurityViewModel")

    private let portRules: [Int: (Severity, String, String, String)] = [
        23:   (.critical,     "Telnet Exposed",            "Telnet transmits credentials in cleartext and has known RCE vulnerabilities.",               "Disable Telnet. Use SSH instead."),
        21:   (.critical,     "FTP Exposed",               "FTP transmits credentials in cleartext. Known exploited vulnerabilities exist.",             "Disable FTP. Use SFTP/SCP instead."),
        5900: (.critical,     "VNC Exposed",               "VNC has known authentication bypass and RCE vulnerabilities.",                               "Disable VNC or restrict to trusted IPs."),
        5800: (.critical,     "VNC Web Interface Exposed", "VNC web console is exposed on the local network.",                                           "Disable VNC web interface."),
        3389: (.critical,     "RDP Exposed",               "Remote Desktop Protocol is a frequent brute-force and RCE target.",                          "Disable RDP or restrict to VPN only."),
        445:  (.warning,      "SMB Exposed",               "SMB has a history of critical vulnerabilities including EternalBlue.",                       "Keep SMB patched. Disable if unused."),
        139:  (.warning,      "NetBIOS Exposed",           "NetBIOS session service exposed.",                                                           "Disable NetBIOS over TCP/IP if unused."),
        22:   (.warning,      "SSH Exposed",               "SSH provides remote shell access. Ensure password auth is disabled.",                        "Use key-based SSH auth. Disable root login."),
        554:  (.warning,      "RTSP Stream Exposed",       "RTSP may allow unauthorized access to camera or media streams.",                             "Restrict RTSP to trusted IPs."),
        1900: (.informational,"UPnP Exposed",              "UPnP can be abused to open router ports without authorization.",                             "Disable UPnP on your router if unused."),
        80:   (.informational,"HTTP Service",              "Unencrypted HTTP service. Traffic is readable on the local network.",                        "Prefer HTTPS."),
        8080: (.informational,"HTTP Alternate Port",       "HTTP service on port 8080.",                                                                 "Confirm this is an intended service.")
    ]

    private let bonjourRules: [String: (Severity, String, String, String)] = [
        "_telnet._tcp":          (.critical,     "Telnet Advertised via Bonjour",  "A Telnet service is broadcasting. Telnet is insecure.",                             "Disable Telnet immediately."),
        "_rfb._tcp":             (.critical,     "VNC Advertised via Bonjour",     "A VNC remote desktop service is broadcasting.",                                      "Disable VNC or restrict to trusted hosts."),
        "_vnc._tcp":             (.critical,     "VNC Advertised via Bonjour",     "A VNC remote desktop service is broadcasting.",                                      "Disable VNC or restrict to trusted hosts."),
        "_ftp._tcp":             (.critical,     "FTP Advertised via Bonjour",     "An FTP service is broadcasting. FTP is insecure.",                                   "Disable FTP. Use SFTP instead."),
        "_remotemanagement._tcp":(.warning,      "Remote Management Enabled",      "Apple Remote Desktop management is discoverable on the network.",                    "Restrict Remote Management to authorized users."),
        "_ssh._tcp":             (.warning,      "SSH Advertised via Bonjour",     "SSH remote access is enabled.",                                                      "Use key-based auth. Disable root login."),
        "_smb._tcp":             (.warning,      "SMB File Sharing Advertised",    "Windows-compatible file sharing is enabled.",                                        "Keep SMB patched. Restrict shares."),
        "_workstation._tcp":     (.warning,      "SMB Workstation Advertised",     "A workstation SMB service is discoverable.",                                         "Ensure SMB shares require authentication."),
        "_http._tcp":            (.informational,"HTTP Service Advertised",        "Unencrypted web service detected.",                                                  "Prefer HTTPS."),
        "_hap._tcp":             (.informational,"HomeKit Accessory Present",      "A HomeKit device is on your network.",                                               "Ensure HomeKit uses a secure home hub."),
        "_printer._tcp":         (.informational,"Network Printer Discovered",     "A network printer is available.",                                                    "Keep printer firmware up to date."),
        "_ipp._tcp":             (.informational,"IPP Printer Discovered",         "An IPP-capable printer is discoverable.",                                            "Keep printer firmware up to date.")
    ]

    init(threatDatabase: ThreatDatabase) {
        self.threatDatabase = threatDatabase
    }

    func assess(devices: [DiscoveredDevice]) async {
        isAssessing = true
        var all: [SecurityFinding] = []
        for device in devices {
            async let pf = portFindings(device: device)
            async let bf = bonjourFindings(device: device)
            async let tf = threatFindings(device: device)
            all += await pf + bf + tf
        }
        var seen = Set<String>()
        findings = all.filter { f in seen.insert("\(f.deviceID)-\(f.title)").inserted }
        isAssessing = false
    }

    func refreshThreatData() async {
        isRefreshing = true
        await threatDatabase.refresh()
        isRefreshing = false
        lastRefreshDate = Date()
    }

    var criticalFindings: [SecurityFinding] { findings.filter { $0.severity == .critical } }
    var warningFindings:  [SecurityFinding] { findings.filter { $0.severity == .warning  } }
    var vulnerableDeviceCount: Int {
        Set(findings.filter { $0.severity >= .warning }.map { $0.deviceID }).count
    }

    // MARK: - Private assessment layers

    private func portFindings(device: DiscoveredDevice) async -> [SecurityFinding] {
        device.openPorts.compactMap { port -> SecurityFinding? in
            guard let (sev, title, desc, rec) = portRules[port] else { return nil }
            return SecurityFinding(deviceID: device.id, severity: sev, title: title,
                                   description: desc, recommendation: rec, source: .portRule)
        }
    }

    private func bonjourFindings(device: DiscoveredDevice) async -> [SecurityFinding] {
        device.bonjourServices.compactMap { svc -> SecurityFinding? in
            guard let (sev, title, desc, rec) = bonjourRules[svc.serviceType] else { return nil }
            return SecurityFinding(deviceID: device.id, severity: sev, title: title,
                                   description: desc, recommendation: rec, source: .bonjourRule)
        }
    }

    private func threatFindings(device: DiscoveredDevice) async -> [SecurityFinding] {
        var results: [SecurityFinding] = []
        for svc in device.bonjourServices {
            let threats = await threatDatabase.lookup(manufacturer: device.manufacturer,
                                                      serviceType: svc.serviceType, port: svc.port)
            for t in threats {
                results.append(SecurityFinding(
                    deviceID: device.id, severity: .critical,
                    title: t.vulnerabilityName,
                    description: t.shortDescription,
                    recommendation: "Apply vendor patch. Reference: \(t.cveID)",
                    source: t.source == .cisa ? .cisaKEV : .nist
                ))
            }
        }
        let mfrThreats = await threatDatabase.lookup(manufacturer: device.manufacturer,
                                                     serviceType: nil, port: nil)
        for t in mfrThreats {
            results.append(SecurityFinding(
                deviceID: device.id, severity: .warning,
                title: t.vulnerabilityName,
                description: t.shortDescription,
                recommendation: "Apply vendor patch. Reference: \(t.cveID)",
                source: t.source == .cisa ? .cisaKEV : .nist
            ))
        }
        return results
    }
}
