// mDNSShark/DesignSystem/AppColors.swift
import SwiftUI

extension SecurityStatus {
    /// The only status-to-colour mapping; every surface that shows a device status calls this.
    var color: Color {
        switch self {
        case .pending:  return AppColors.pending
        case .secure:   return AppColors.secure
        case .warning:  return AppColors.warning
        case .critical: return AppColors.critical
        }
    }
}

enum AppColors {
    static let secure      = Color(red: 0.204, green: 0.780, blue: 0.349)  // #34C759
    static let warning     = Color(red: 1.000, green: 0.624, blue: 0.039)  // #FF9F0A
    static let critical    = Color(red: 1.000, green: 0.231, blue: 0.188)  // #FF3B30
    static let info        = Color(red: 0.039, green: 0.518, blue: 1.000)  // #0A84FF

    static let pending     = Color(.systemGray)

    enum PacketProtocol {
        static let dns   = Color.orange
        static let tcp   = Color.purple
        static let udp   = Color.teal
        static let icmp  = Color.red
        static let mdns  = Color.blue
        static let https = Color.green
        static let other = Color.gray

        static func color(for name: String) -> Color {
            switch name.uppercased() {
            case "DNS":   return dns
            case "TCP":   return tcp
            case "UDP":   return udp
            case "ICMP":  return icmp
            case "MDNS":  return mdns
            case "HTTPS": return https
            default:      return other
            }
        }
    }
}
