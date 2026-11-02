// mDNSShark/Devices/DevicesView.swift
import SwiftUI

struct DevicesView: View {
    @EnvironmentObject var scanVM: NetworkScanViewModel
    @EnvironmentObject var securityVM: SecurityViewModel
    @EnvironmentObject var deepLinks: DeepLinkRouter

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 12) {
                    if scanVM.devices.isEmpty {
                        VStack(spacing: 12) {
                            Image(systemName: "magnifyingglass").font(.system(size: 48)).foregroundColor(.secondary)
                            Text("No devices discovered yet.").foregroundColor(.secondary)
                        }.padding(scanVM.unattachedServices.isEmpty ? 40 : 20)
                    } else {
                        ForEach(scanVM.devices) { device in
                            let findings = securityVM.findings.filter { $0.deviceID == device.id }
                            let issueCount = findings.count
                            let badgeColor = SecurityStatus.of(findings: findings, settled: device.probesSettled, probed: device.wasProbed).color
                            NavigationLink(destination: DeviceDetailView(device: device)) {
                                DeviceCardView(device: device, issueCount: issueCount, badgeColor: badgeColor)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    if !scanVM.unattachedServices.isEmpty {
                        UnattachedServicesSection(services: scanVM.unattachedServices)
                            .padding(.top, 8)
                    }
                }
                .padding(.horizontal).padding(.top, 8)
                .animation(.default, value: scanVM.devices.map(\.id))
            }
            .navigationDestination(item: $deepLinks.deviceLinkID) { id in
                if let device = scanVM.devices.first(where: { $0.id == id }) { DeviceDetailView(device: device) }
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar(.hidden, for: .navigationBar)
        }
    }
}
