// mDNSShark/Models/TopologyNode.swift
import Foundation
import CoreGraphics

/// `pending` is a device whose probes have not settled yet; it is neither secure nor vulnerable.
enum SecurityStatus: Hashable {
    case pending, secure, informational, warning, critical

    /// Spoken form for VoiceOver, since the UI otherwise conveys the status by border colour alone.
    var accessibilityName: String {
        switch self {
        case .pending:       return "pending"
        case .secure:        return "secure"
        case .informational: return "informational"
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

    /// Findings alone never colour a node whose probes are still running.
    static func status(findings: [SecurityFinding], settled: Bool) -> SecurityStatus {
        guard settled else { return .pending }
        switch findings.worstDeviceSeverity {
        case .critical:      return .critical
        case .warning:       return .warning
        case .informational: return .informational
        default:             return .secure
        }
    }

    /// Chip semantics: no chip shows every device, each chip shows its own status, and Secure also covers informational-only devices.
    static func matchesFilters(_ status: SecurityStatus, _ filters: Set<SecurityStatus>) -> Bool {
        filters.isEmpty || filters.contains(status) || (status == .informational && filters.contains(.secure))
    }

    /// VoiceOver text for the node: "<hostname>, <ip>, <status>[, vendor advisory]".
    var accessibilityLabel: String {
        var text = "\(device.hostname), \(device.ipAddress), \(securityStatus.accessibilityName)"
        if device.securityFindings.hasVendorAdvisory { text += ", vendor advisory" }
        return text
    }
}
