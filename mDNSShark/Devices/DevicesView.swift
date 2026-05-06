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
                            let issueCount = findings.filter { $0.severity >= .warning }.count
                            NavigationLink(destination: DeviceDetailView(device: enriched(device, findings))) {
                                DeviceCardView(device: device, issueCount: issueCount)
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
