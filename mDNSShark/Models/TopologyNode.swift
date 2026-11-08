// mDNSShark/Models/TopologyNode.swift
import Foundation
import CoreGraphics

/// The one device status every screen uses (header, Topology, Devices, legend). `pending` is a device whose probes have not settled yet; `notProbed` is one that was deliberately never probed.
/// Secure means no warning or critical finding about the device itself; informational and vendor-advisory findings never change it.
enum SecurityStatus: Hashable, CaseIterable {
    case pending, notProbed, secure, warning, critical

    /// Findings alone never colour a device whose probes are still running; a device that was never probed is not called secure.
    static func of(findings: [SecurityFinding], settled: Bool, probed: Bool = true) -> SecurityStatus {
        guard settled else { return .pending }
        switch findings.worstDeviceSeverity {
        case .critical: return .critical
        case .warning:  return .warning
        default:        return probed ? .secure : .notProbed
        }
    }

    var label: String { accessibilityName.capitalized }

    /// Spoken form for VoiceOver, since the UI otherwise conveys the status by border colour alone.
    var accessibilityName: String {
        switch self {
        case .pending:       return "pending"
        case .notProbed:     return "not probed"
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
    /// True when a nearby Bluetooth peripheral is suggested (inferred) for this device; informational only, the status never changes.
    var hasBluetoothSuggestion: Bool

    /// Name of the custom VoiceOver action that opens the device detail at its Bluetooth card.
    static let bluetoothActionName = "Show Bluetooth details"

    init(device: DiscoveredDevice, position: CGPoint = .zero, bluetoothSuggested: Bool = false) {
        self.id = device.id; self.device = device; self.position = position
        self.hasBluetoothSuggestion = bluetoothSuggested
        self.securityStatus = Self.status(findings: device.securityFindings, settled: device.probesSettled, probed: device.wasProbed)
    }

    static func status(findings: [SecurityFinding], settled: Bool, probed: Bool = true) -> SecurityStatus { .of(findings: findings, settled: settled, probed: probed) }

    /// Chip semantics: no chip shows every device, each chip shows its own status.
    static func matchesFilters(_ status: SecurityStatus, _ filters: Set<SecurityStatus>) -> Bool {
        filters.isEmpty || filters.contains(status)
    }

    /// VoiceOver text for the node: "<hostname>, <ip>, <status>[, vendor advisory][, on another network][, Bluetooth device suggested]".
    var accessibilityLabel: String {
        var text = "\(device.hostname), \(device.ipAddress), \(securityStatus.accessibilityName)"
        if device.securityFindings.hasVendorAdvisory { text += ", vendor advisory" }
        if device.isOnLocalSubnet == false { text += ", on another network" }
        if hasBluetoothSuggestion { text += ", Bluetooth device suggested" }
        return text
    }
}
