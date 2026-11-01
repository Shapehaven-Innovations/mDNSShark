// mDNSShark/Topology/TopologyNodeView.swift
import SwiftUI

/// One node standing for every advertisement that resolved to no device; drawn dashed and grey so it reads as not-a-device.
struct ServicesGroupNodeView: View {
    let count: Int

    /// VoiceOver text; the dashed grey border alone says "not a device".
    static func accessibilityLabel(count: Int) -> String {
        "\(count) \(count == 1 ? "service" : "services") without a device"
    }

    var body: some View {
        VStack(spacing: 4) {
            ZStack {
                RoundedRectangle(cornerRadius: 12)
                    .fill(Color(.secondarySystemBackground))
                    .frame(width: 52, height: 52)
                    .overlay(RoundedRectangle(cornerRadius: 12)
                        .stroke(Color(.systemGray), style: StrokeStyle(lineWidth: 2, dash: [4, 3])))
                Image(systemName: "network").font(.title2).foregroundColor(.secondary)
            }
            Text("\(count) \(count == 1 ? "service" : "services")")
                .font(.system(size: 9, weight: .medium))
                .lineLimit(1).frame(maxWidth: 72)
            Text("no device")
                .font(.system(size: 8))
                .foregroundColor(.secondary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(Self.accessibilityLabel(count: count))
    }
}

struct TopologyNodeView: View {
    let node: TopologyNode

    private var borderColor: Color {
        switch node.securityStatus {
        case .pending:       return Color(.systemGray)
        case .secure:        return AppColors.secure
        case .informational: return AppColors.info
        case .warning:       return AppColors.warning
        case .critical:      return AppColors.critical
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
            .overlay(alignment: .topTrailing) {
                if node.device.securityFindings.hasVendorAdvisory {
                    Image(systemName: "info.circle.fill")
                        .font(.system(size: 20, weight: .bold))
                        .symbolRenderingMode(.palette)
                        .foregroundStyle(.white, AppColors.info)
                        .background(Circle().fill(Color(.systemBackground)).padding(-2))
                        .offset(x: 8, y: -8)
                }
            }
            Text(node.device.hostname)
                .font(.system(size: 9, weight: .medium))
                .lineLimit(1).frame(maxWidth: 72)
            Text(node.device.ipAddress)
                .font(.system(size: 8))
                .foregroundColor(.secondary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(node.accessibilityLabel)
    }
}
