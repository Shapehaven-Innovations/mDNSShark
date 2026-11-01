// mDNSShark/Header/AppHeaderView.swift
import SwiftUI

struct AppHeaderView: View {
    @EnvironmentObject var coordinator: AppCoordinator

    var body: some View {
        // The vulnerable set is built once per render; secure restates SecurityViewModel.secureDeviceCount(among:) against it.
        let devices = coordinator.networkScanViewModel.devices
        let vulnerableIDs = coordinator.securityViewModel.vulnerableDeviceIDs
        let secureCount = devices.filter { $0.probesSettled && !vulnerableIDs.contains($0.id) }.count
        let pendingCount = devices.filter { !$0.probesSettled }.count
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
                    coordinator.networkScanViewModel.startScan()
                } label: {
                    Label("Scan", systemImage: "arrow.clockwise")
                        .font(.subheadline.weight(.semibold))
                        .padding(.horizontal, 12).padding(.vertical, 6)
                        .background(Color(.secondarySystemBackground))
                        .clipShape(Capsule())
                }
                .disabled(coordinator.networkScanViewModel.isScanning)
            }
            .padding(.horizontal, 16).padding(.vertical, 10)

            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    statusBadge(icon: "wifi",
                                text: coordinator.networkScanViewModel.networkCIDR,
                                color: Color(.systemGray2))
                    AppBadge(text: "\(devices.count) devices", color: Color(.systemGray))
                    if serviceCount > 0 {
                        AppBadge(text: "\(serviceCount) \(serviceCount == 1 ? "service" : "services")", color: AppColors.info)
                    }
                    AppBadge(text: "\(secureCount) secure", color: AppColors.secure)
                    if !vulnerableIDs.isEmpty {
                        AppBadge(text: "\(vulnerableIDs.count) vulnerable", color: AppColors.critical)
                    }
                    if coordinator.networkScanViewModel.isScanning {
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
    private var serviceCount: Int { coordinator.networkScanViewModel.unattachedServices.count }

    private func statusBadge(icon: String, text: String, color: Color) -> some View {
        Label(text, systemImage: icon)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 10).padding(.vertical, 5)
            .background(Color(.tertiarySystemBackground))
            .clipShape(Capsule())
    }
}
