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
    var onBluetoothBadgeTap: () -> Void = {}

    private var borderColor: Color { node.securityStatus.color }

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
            .overlay(alignment: .bottomLeading) {
                if node.device.isOnLocalSubnet == false {
                    Image(systemName: "arrow.triangle.branch")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.white)
                        .padding(3)
                        .background(Circle().fill(AppColors.pending))
                        .offset(x: -6, y: 6)
                }
            }
            .overlay(alignment: .bottomTrailing) {
                // Mirrors the off-network badge; VoiceOver hears it through the node label and a custom action instead.
                if node.hasBluetoothSuggestion {
                    Button(action: onBluetoothBadgeTap) {
                        Image(systemName: BluetoothSymbol.name)
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(.white)
                            .padding(3)
                            .background(Circle().fill(AppColors.info))
                    }
                    .buttonStyle(.plain)
                    .contentShape(Circle().inset(by: -6))
                    .offset(x: 6, y: 6)
                    .transition(.scale.combined(with: .opacity))
                    .accessibilityHidden(true)
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
        // Built conditionally inside the actions block so the node keeps its identity when a suggestion appears.
        .accessibilityActions {
            if node.hasBluetoothSuggestion {
                Button { onBluetoothBadgeTap() } label: { Text(TopologyNode.bluetoothActionName) }
            }
        }
    }
}
