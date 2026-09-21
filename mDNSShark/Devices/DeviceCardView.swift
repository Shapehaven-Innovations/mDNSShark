// mDNSShark/Devices/DeviceCardView.swift
import SwiftUI

struct DeviceCardView: View {
    let device: DiscoveredDevice
    let issueCount: Int
    let badgeColor: Color

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
                             color: badgeColor)
                }
                Divider()
                // alignment: .leading — LazyVGrid defaults to .center, which
                // centers each cell's VStack independently within its column
                // using that VStack's own intrinsic width. MAC ("0c:ea:14:...",
                // 17 chars) and OS ("Linux (embedded, likely...)", wider pre-
                // truncation) share column 1 but have different intrinsic
                // widths, so they land at different x-offsets instead of a
                // shared left edge. .leading pins every cell flush to its
                // column's leading edge regardless of content width.
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], alignment: .leading, spacing: 8) {
                    cell("MAC",          device.macAddress ?? "Unknown")
                    cell("Manufacturer", device.manufacturer ?? "Unknown")
                    cell("OS",           device.displayInferredOS  ?? "Unknown")
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
