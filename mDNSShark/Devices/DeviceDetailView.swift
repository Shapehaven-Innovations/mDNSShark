// mDNSShark/Devices/DeviceDetailView.swift
import SwiftUI

struct DeviceDetailView: View {
    @EnvironmentObject var coordinator: AppCoordinator
    // Navigation-time snapshot. Only a fallback — see `device` below.
    private let snapshot: DiscoveredDevice

    init(device: DiscoveredDevice) { snapshot = device }

    /// The live row for this device, re-read from the coordinator on every
    /// body evaluation, with the current security findings applied.
    ///
    /// Reading `coordinator` here — rather than rendering whatever value
    /// the parent passed in — is what keeps an already-pushed detail
    /// screen updating as enrichment streams in. `@EnvironmentObject`
    /// registers a dependency on `coordinator.objectWillChange`, so any
    /// devices/findings mutation re-runs this body. A parent-supplied
    /// value alone cannot: SwiftUI decides whether to re-run a child's
    /// body by comparing the old and new view values field-by-field using
    /// each field's `Equatable`, and `DiscoveredDevice ==` compares only
    /// `id` — so a fresh copy carrying a newly-discovered MAC/manufacturer/
    /// OS diffs as "unchanged" and is silently dropped, leaving the screen
    /// stuck on "Unknown". The snapshot is used only if the row has since
    /// left the live list.
    private var device: DiscoveredDevice {
        var live = coordinator.networkScanViewModel.devices.first { $0.id == snapshot.id } ?? snapshot
        live.securityFindings = coordinator.securityViewModel.findings.filter { $0.deviceID == snapshot.id }
        return live
    }

    var body: some View {
        let device = self.device
        ScrollView {
            VStack(spacing: 16) {
                CardView {
                    HStack(spacing: 16) {
                        Image(systemName: device.deviceIcon).font(.system(size: 40)).foregroundColor(AppColors.info)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(device.hostname).font(.title2.bold())
                            Text(device.ipAddress).foregroundColor(.secondary)
                            if let os = device.displayInferredOS { Text(os).font(.caption).foregroundColor(.secondary) }
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
                        row("Inferred OS",  device.displayInferredOS  ?? "Unknown")
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
        // .firstTextBaseline, not the default .center: MAC/OS values can now
        // be long enough to wrap (a real MAC via arpTableLookup is 17
        // characters), and a wrapped 2-line value under center alignment
        // pulls the single-line label down to the vertical midpoint instead
        // of lining up with the value's first line.
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundColor(.secondary).font(.subheadline)
            Spacer()
            Text(value).font(.subheadline.weight(.medium)).multilineTextAlignment(.trailing)
        }
    }
}
