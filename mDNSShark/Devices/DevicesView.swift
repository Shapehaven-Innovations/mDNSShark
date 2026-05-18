// mDNSShark/Devices/DevicesView.swift
import SwiftUI

struct DevicesView: View {
    @EnvironmentObject var coordinator: AppCoordinator

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 12) {
                    if coordinator.networkScanViewModel.devices.isEmpty {
                        VStack(spacing: 12) {
                            Image(systemName: "magnifyingglass").font(.system(size: 48)).foregroundColor(.secondary)
                            Text("No devices discovered yet.").foregroundColor(.secondary)
                        }.padding(40)
                    } else {
                        ForEach(coordinator.networkScanViewModel.devices) { device in
                            let findings = coordinator.securityViewModel.findings.filter { $0.deviceID == device.id }
                            let issueCount = findings.count
                            let badgeColor: Color = {
                                if findings.contains(where: { $0.severity == .critical }) { return AppColors.critical }
                                if findings.contains(where: { $0.severity == .warning })  { return AppColors.warning }
                                if !findings.isEmpty { return AppColors.info }
                                return AppColors.secure
                            }()
                            NavigationLink(destination: DeviceDetailView(device: enriched(device, findings))) {
                                DeviceCardView(device: device, issueCount: issueCount, badgeColor: badgeColor)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
                .padding(.horizontal).padding(.top, 8)
            }
            .navigationBarHidden(true)
        }
    }

    private func enriched(_ d: DiscoveredDevice, _ findings: [SecurityFinding]) -> DiscoveredDevice {
        var copy = d; copy.securityFindings = findings; return copy
    }
}
