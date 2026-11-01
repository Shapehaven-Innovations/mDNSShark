// mDNSShark/Models/TopologyNode.swift
import Foundation
import CoreGraphics

/// The one device status every screen uses (header, Topology, Devices, legend). `pending` is a device whose probes have not settled yet.
/// Secure means no warning or critical finding about the device itself; informational and vendor-advisory findings never change it.
enum SecurityStatus: Hashable, CaseIterable {
    case pending, secure, warning, critical

    /// Findings alone never colour a device whose probes are still running.
    static func of(findings: [SecurityFinding], settled: Bool) -> SecurityStatus {
        guard settled else { return .pending }
        switch findings.worstDeviceSeverity {
        case .critical: return .critical
        case .warning:  return .warning
        default:        return .secure
        }
    }

    var label: String { accessibilityName.capitalized }

    /// Spoken form for VoiceOver, since the UI otherwise conveys the status by border colour alone.
    var accessibilityName: String {
        switch self {
        case .pending:       return "pending"
        case .secure:        return "secure"
        case .warning:       return "warning"
        case .critical:      return "critical"
        }
    }
}

struct TopologyNode: Identifiable {
    let id: UUID
    let device: DiscoveredDevice
    var position: CGPoint
    var securityStatus: SecurityStatus

    init(device: DiscoveredDevice, position: CGPoint = .zero) {
        self.id = device.id; self.device = device; self.position = position
        self.securityStatus = Self.status(findings: device.securityFindings, settled: device.probesSettled)
    }

    static func status(findings: [SecurityFinding], settled: Bool) -> SecurityStatus { .of(findings: findings, settled: settled) }

    /// Chip semantics: no chip shows every device, each chip shows its own status.
    static func matchesFilters(_ status: SecurityStatus, _ filters: Set<SecurityStatus>) -> Bool {
        filters.isEmpty || filters.contains(status)
    }

    /// VoiceOver text for the node: "<hostname>, <ip>, <status>[, vendor advisory]".
    var accessibilityLabel: String {
        var text = "\(device.hostname), \(device.ipAddress), \(securityStatus.accessibilityName)"
        if device.securityFindings.hasVendorAdvisory { text += ", vendor advisory" }
        return text
    }
}
