// mDNSShark/Topology/NetworksSheet.swift
import SwiftUI

/// This phone's own networks and gateways, then the devices that sit outside them, all as literal values.
struct NetworksSheet: View {
    @EnvironmentObject var scanVM: NetworkScanViewModel
    @Environment(\.dismiss) private var dismiss

    private var offNetwork: [DiscoveredDevice] { scanVM.devices.filter { $0.isOnLocalSubnet == false } }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    HStack {
                        Text("Networks").font(.title3.bold())
                        Spacer()
                        Button("Done") { dismiss() }
                    }
                    CardView {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("This phone").font(.headline)
                            Divider()
                            lines("Networks", scanVM.ownSubnetCIDRs)
                            lines("Gateways", scanVM.gatewaysIPv4)
                        }
                    }
                    CardView {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("Devices outside this phone's network").font(.headline)
                            Divider()
                            if offNetwork.isEmpty {
                                Text("None found").font(.subheadline).foregroundColor(.secondary)
                            }
                            ForEach(offNetwork) { device in
                                NavigationLink(destination: DeviceDetailView(device: device)) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(verbatim: device.ipAddress).font(.subheadline.weight(.semibold))
                                        Text(verbatim: device.hostname).font(.caption).foregroundColor(.secondary)
                                        ForEach(device.networkNote(ownCIDRs: scanVM.ownSubnetCIDRs).dropFirst(), id: \.self) { line in
                                            Text(verbatim: line).font(.caption).foregroundColor(.secondary)
                                        }
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                }
                                .buttonStyle(.plain)
                                if device.id != offNetwork.last?.id { Divider() }
                            }
                        }
                    }
                }
                .padding()
            }
            .toolbar(.hidden, for: .navigationBar)
        }
    }

    private func lines(_ label: String, _ values: [String]) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).font(.subheadline).foregroundColor(.secondary)
            Spacer()
            Text(verbatim: values.isEmpty ? "Unknown" : values.joined(separator: ", "))
                .font(.subheadline.weight(.medium)).multilineTextAlignment(.trailing).textSelection(.enabled)
        }
    }
}
