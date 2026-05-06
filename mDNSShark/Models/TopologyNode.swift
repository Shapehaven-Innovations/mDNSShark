// mDNSShark/Models/TopologyNode.swift
import Foundation
import CoreGraphics

enum SecurityStatus: Hashable { case secure, warning, critical }

struct TopologyNode: Identifiable {
    let id: UUID
    let device: DiscoveredDevice
    var position: CGPoint
    var securityStatus: SecurityStatus

    init(device: DiscoveredDevice, position: CGPoint = .zero) {
        self.id = device.id; self.device = device; self.position = position
        let max = device.securityFindings.map { $0.severity }.max()
        switch max {
        case .critical: self.securityStatus = .critical
        case .warning:  self.securityStatus = .warning
        default:        self.securityStatus = .secure
        }
    }
}
