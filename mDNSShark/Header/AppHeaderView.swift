// mDNSShark/Header/AppHeaderView.swift
import SwiftUI

struct AppHeaderView: View {
    @EnvironmentObject var scanVM: NetworkScanViewModel
    @EnvironmentObject var securityVM: SecurityViewModel

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
                    scanVM.startScan()
                } label: {
                    Label("Scan", systemImage: "arrow.clockwise")
                        .font(.subheadline.weight(.semibold))
                        .padding(.horizontal, 12).padding(.vertical, 6)
                        .background(Color(.secondarySystemBackground))
                        .clipShape(Capsule())
                }
                .disabled(scanVM.isScanning)
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
                    // One chip per non-empty status, in the same colour as the node, badge and legend. Pending has its own chip below.
                    ForEach([SecurityStatus.secure, .warning, .critical], id: \.self) { status in
                        if let n = counts[status], n > 0 { AppBadge(text: "\(n) \(status.label.lowercased())", color: status.color) }
                    }
                    if scanVM.isScanning {
                        AppBadge(text: "Scanning…", color: Color(.systemGray))
                            .accessibilityLabel("Scanning for devices")
                    } else if pendingCount > 0 {
                        AppBadge(text: "\(pendingCount) pending", color: Color(.systemGray))
                            .accessibilityLabel("\(pendingCount) \(pendingCount == 1 ? "device" : "devices") still being probed")
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
        Label(text, systemImage: icon)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 10).padding(.vertical, 5)
            .background(Color(.tertiarySystemBackground))
            .clipShape(Capsule())
    }
}
