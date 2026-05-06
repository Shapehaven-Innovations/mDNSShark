// mDNSShark/Devices/DeviceDetailView.swift
import SwiftUI

struct DeviceDetailView: View {
    let device: DiscoveredDevice

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                CardView {
                    HStack(spacing: 16) {
                        Image(systemName: device.deviceIcon).font(.system(size: 40)).foregroundColor(AppColors.info)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(device.hostname).font(.title2.bold())
                            Text(device.ipAddress).foregroundColor(.secondary)
                            if let os = device.inferredOS { Text(os).font(.caption).foregroundColor(.secondary) }
                        }
                        Spacer()
                    }
                }

                CardView {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Device Info").font(.headline)
                        Divider()
                        row("MAC Address",  device.macAddress ?? "Unknown")
                        row("Manufacturer", device.manufacturer ?? "Unknown")
                        row("Inferred OS",  device.inferredOS  ?? "Unknown")
                        row("Open Ports",   device.openPorts.isEmpty ? "None" : device.openPorts.map { String($0) }.joined(separator: ", "))
                    }
                }

                if !device.bonjourServices.isEmpty {
                    CardView {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("Bonjour Services").font(.headline)
                            Divider()
                            ForEach(device.bonjourServices) { svc in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(svc.serviceType).font(.subheadline.weight(.semibold))
                                    Text(svc.serviceName).font(.caption).foregroundColor(.secondary)
                                    if svc.port > 0 { Text("Port \(svc.port)").font(.caption2).foregroundColor(.secondary) }
                                }
                                if svc.id != device.bonjourServices.last?.id { Divider() }
                            }
                        }
                    }
                }

                if !device.securityFindings.isEmpty {
                    CardView {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("Security Findings").font(.headline)
                            Divider()
                            ForEach(device.securityFindings) { finding in
                                FindingRowView(finding: finding)
                                if finding.id != device.securityFindings.last?.id { Divider() }
                            }
                        }
                    }
                }
            }
            .padding(.horizontal).padding(.vertical, 8)
        }
        .navigationTitle(device.hostname)
        .navigationBarTitleDisplayMode(.inline)
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).foregroundColor(.secondary).font(.subheadline)
            Spacer()
            Text(value).font(.subheadline.weight(.medium)).multilineTextAlignment(.trailing)
        }
    }
}
