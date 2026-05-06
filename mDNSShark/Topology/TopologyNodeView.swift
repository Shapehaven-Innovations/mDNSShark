// mDNSShark/Topology/TopologyNodeView.swift
import SwiftUI

struct TopologyNodeView: View {
    let node: TopologyNode

    private var borderColor: Color {
        switch node.securityStatus {
        case .secure:   return AppColors.secure
        case .warning:  return AppColors.warning
        case .critical: return AppColors.critical
        }
    }

    var body: some View {
        VStack(spacing: 4) {
            ZStack {
                RoundedRectangle(cornerRadius: 12)
                    .fill(Color(.secondarySystemBackground))
                    .frame(width: 52, height: 52)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(borderColor, lineWidth: 2))
                Image(systemName: node.device.deviceIcon)
                    .font(.title2).foregroundColor(borderColor)
            }
            Text(node.device.hostname)
                .font(.system(size: 9, weight: .medium))
                .lineLimit(1).frame(maxWidth: 72)
            Text(node.device.ipAddress)
                .font(.system(size: 8))
                .foregroundColor(.secondary)
        }
    }
}
