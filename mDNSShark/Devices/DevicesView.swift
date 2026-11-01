// mDNSShark/Devices/DevicesView.swift
import SwiftUI

struct DevicesView: View {
    @EnvironmentObject var coordinator: AppCoordinator

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 12) {
                    if coordinator.networkScanViewModel.devices.isEmpty {
                        VStack(spacing: 12) {
                            Image(systemName: "magnifyingglass").font(.system(size: 48)).foregroundColor(.secondary)
                            Text("No devices discovered yet.").foregroundColor(.secondary)
                        }.padding(coordinator.networkScanViewModel.unattachedServices.isEmpty ? 40 : 20)
                    } else {
                        ForEach(coordinator.networkScanViewModel.devices) { device in
                            let findings = coordinator.securityViewModel.findings.filter { $0.deviceID == device.id }
                            let issueCount = findings.count
                            // Same semantics as Topology: grey until probes settle, and vendor advisories never raise the colour above informational.
                            let badgeColor: Color = {
                                guard device.probesSettled else { return Color(.systemGray) }
                                switch findings.worstDeviceSeverity {
                                case .some(.critical):      return AppColors.critical
                                case .some(.warning):       return AppColors.warning
                                case .some(.informational): return AppColors.info
                                case .none:                 return findings.hasVendorAdvisory ? AppColors.info : AppColors.secure
                                }
                            }()
                            NavigationLink(destination: DeviceDetailView(device: device)) {
                                DeviceCardView(device: device, issueCount: issueCount, badgeColor: badgeColor)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    if !coordinator.networkScanViewModel.unattachedServices.isEmpty {
                        UnattachedServicesSection(services: coordinator.networkScanViewModel.unattachedServices)
                            .padding(.top, 8)
                    }
                }
                .padding(.horizontal).padding(.top, 8)
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar(.hidden, for: .navigationBar)
        }
    }
}
