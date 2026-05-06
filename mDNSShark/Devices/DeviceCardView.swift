// mDNSShark/Devices/DeviceCardView.swift
import SwiftUI

struct DeviceCardView: View {
    let device: DiscoveredDevice
    let issueCount: Int

    var body: some View {
        CardView {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Image(systemName: device.deviceIcon).font(.title2).foregroundColor(AppColors.info).frame(width: 32)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(device.hostname).font(.headline)
                        Text(device.ipAddress).font(.subheadline).foregroundColor(.secondary)
                    }
                    Spacer()
                    AppBadge(text: issueCount == 0 ? "0 issues" : "\(issueCount) issues",
                             color: issueCount == 0 ? AppColors.secure : AppColors.critical)
                }
                Divider()
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                    cell("MAC",          device.macAddress ?? "Unknown")
                    cell("Manufacturer", device.manufacturer ?? "Unknown")
                    cell("OS",           device.inferredOS  ?? "Unknown")
                    cell("Open Ports",   device.openPorts.isEmpty ? "None" : "\(device.openPorts.count) detected")
                }
            }
        }
    }

    private func cell(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption).foregroundColor(.secondary)
            Text(value).font(.subheadline.weight(.medium)).lineLimit(1)
        }
    }
}
