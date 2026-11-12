// mDNSShark/Header/AppHeaderView.swift
import SwiftUI

/// Text for the header's Bluetooth chip; the count comes from advertisements and never joins the LAN device count.
enum BluetoothHeaderChip {
    static func text(nearby: Int, isScanning: Bool) -> String? {
        if isScanning { return "Bluetooth scanning…" }
        return nearby == 0 ? nil : "\(nearby) Bluetooth nearby"
    }

    static func accessibilityLabel(nearby: Int) -> String {
        "\(nearby) Bluetooth \(nearby == 1 ? "device" : "devices") nearby, from advertisements"
    }

    static let hint = "Opens Devices filtered to Bluetooth"

    /// The label keeps the count; the value says a scan is running.
    static func accessibilityValue(isScanning: Bool) -> String { isScanning ? "Scanning" : "" }
}

struct AppHeaderView: View {
    @EnvironmentObject var scanVM: NetworkScanViewModel
    @EnvironmentObject var securityVM: SecurityViewModel
    @EnvironmentObject var bluetoothVM: BluetoothViewModel
    @EnvironmentObject var coordinator: AppCoordinator

    var body: some View {
        let devices = scanVM.devices
        let counts = securityVM.statusCounts(among: devices)
        let pendingCount = counts[.pending] ?? 0
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                HStack(spacing: 8) {
                    Image("SharkIcon")
                        .resizable()
                        .scaledToFit()
                        .frame(height: 52)
                    VStack(alignment: .leading, spacing: 0) {
                        Text("mDNSShark").font(.headline.bold())
                        Text("Network Security Scanner").font(.caption).foregroundColor(.secondary)
                    }
                }
                Spacer()
                Button {
                    coordinator.startHeaderScan()
                } label: {
                    Label("Scan", systemImage: "arrow.clockwise")
                        .font(.subheadline.weight(.semibold))
                        .padding(.horizontal, 12).padding(.vertical, 6)
                        .background(Color(.secondarySystemBackground))
                        .clipShape(Capsule())
                }
                .disabled(coordinator.isAnyScanRunning)
            }
            .padding(.horizontal, 16).padding(.vertical, 10)

            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    statusBadge(icon: "wifi",
                                text: scanVM.networkCIDR,
                                color: Color(.systemGray2))
                    AppBadge(text: "\(devices.count) devices", color: Color(.systemGray))
                    if serviceCount > 0 {
                        AppBadge(text: "\(serviceCount) \(serviceCount == 1 ? "service" : "services")", color: AppColors.info)
                    }
                    if let text = BluetoothHeaderChip.text(nearby: bluetoothVM.nearbyCount, isScanning: bluetoothVM.isScanning) {
                        Button { coordinator.showDevices(filter: .bluetooth) } label: {
                            AppBadge(text: text, color: AppColors.info)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(BluetoothHeaderChip.accessibilityLabel(nearby: bluetoothVM.nearbyCount))
                        .accessibilityValue(BluetoothHeaderChip.accessibilityValue(isScanning: bluetoothVM.isScanning))
                        .accessibilityHint(BluetoothHeaderChip.hint)
                    }
                    // One chip per non-empty status, in the same colour as the node, badge and legend. Pending has its own chip below.
                    ForEach([SecurityStatus.secure, .warning, .critical], id: \.self) { status in
                        if let n = counts[status], n > 0 { AppBadge(text: "\(n) \(status.label.lowercased())", color: status.color) }
                    }
                    // One badge whose text changes, so the view keeps its identity instead of being swapped when a scan starts or ends.
                    if scanVM.isScanning || pendingCount > 0 {
                        AppBadge(text: scanVM.isScanning ? "Scanning…" : "\(pendingCount) pending", color: AppColors.pending)
                            .accessibilityLabel(scanVM.isScanning ? "Scanning for devices"
                                : "\(pendingCount) \(pendingCount == 1 ? "device" : "devices") still being probed")
                    }
                }
                .padding(.horizontal, 16).padding(.bottom, 8)
            }
        }
        .background(Color(.systemBackground))
    }

    /// Services with no resolved device; kept out of the device, secure and vulnerable counts.
    private var serviceCount: Int { scanVM.unattachedServices.count }

    private func statusBadge(icon: String, text: String, color: Color) -> some View {
        Label { Text(text) } icon: { WifiGlyph().frame(width: 14, height: 14) }
            .font(.caption.weight(.medium))
            .padding(.horizontal, 10).padding(.vertical, 5)
            .background(Color(.tertiarySystemBackground))
            .clipShape(Capsule())
    }
}
