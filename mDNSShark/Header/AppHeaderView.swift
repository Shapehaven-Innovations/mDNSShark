// mDNSShark/Header/AppHeaderView.swift
import SwiftUI

struct AppHeaderView: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @AppStorage("preferredColorScheme") private var colorSchemeRaw: Int = 0

    var body: some View {
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

                Button { colorSchemeRaw = (colorSchemeRaw + 1) % 3 } label: {
                    Image(systemName: colorSchemeIcon).font(.title3)
                }
            }
            .padding(.horizontal, 16).padding(.vertical, 10)

            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    statusBadge(icon: "wifi",
                                text: coordinator.networkScanViewModel.networkCIDR,
                                color: Color(.systemGray2))
                    AppBadge(text: "\(coordinator.networkScanViewModel.devices.count) devices",
                             color: Color(.systemGray))
                    AppBadge(text: "\(secureCount) secure",    color: AppColors.secure)
                    if coordinator.securityViewModel.vulnerableDeviceCount > 0 {
                        AppBadge(text: "\(coordinator.securityViewModel.vulnerableDeviceCount) vulnerable",
                                 color: AppColors.critical)
                    }
                }
                .padding(.horizontal, 16).padding(.bottom, 8)
            }
        }
        .background(Color(.systemBackground))
    }

    private var secureCount: Int {
        let withFindings = Set(coordinator.securityViewModel.findings.map { $0.deviceID })
        return coordinator.networkScanViewModel.devices.filter { !withFindings.contains($0.id) }.count
    }

    private var colorSchemeIcon: String {
        switch colorSchemeRaw { case 1: return "sun.max.fill"; case 2: return "moon.fill"; default: return "circle.lefthalf.filled" }
    }

    private func statusBadge(icon: String, text: String, color: Color) -> some View {
        Label(text, systemImage: icon)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 10).padding(.vertical, 5)
            .background(Color(.tertiarySystemBackground))
            .clipShape(Capsule())
    }
}
