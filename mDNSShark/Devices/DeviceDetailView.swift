// mDNSShark/Devices/DeviceDetailView.swift
import SwiftUI
import DeviceFingerprint

struct DeviceDetailView: View {
    @EnvironmentObject var scanVM: NetworkScanViewModel
    @EnvironmentObject var securityVM: SecurityViewModel
    @Environment(\.dismiss) private var dismiss
    // Navigation-time snapshot. Only a fallback; see `device` below.
    private let snapshot: DiscoveredDevice

    init(device: DiscoveredDevice) { snapshot = device }

    /// The live row for this device, re-read from the scan and security view models on every
    /// body evaluation, with the current security findings applied.
    ///
    /// Reading the view models here (rather than rendering whatever value
    /// the parent passed in) is what keeps an already-pushed detail
    /// screen updating as enrichment streams in. `@EnvironmentObject`
    /// registers a dependency on each object's `objectWillChange`, so any
    /// devices/findings mutation re-runs this body. A parent-supplied
    /// value alone cannot: SwiftUI decides whether to re-run a child's
    /// body by comparing the old and new view values field-by-field using
    /// each field's `Equatable`, and `DiscoveredDevice ==` compares only
    /// `id`, so a fresh copy carrying a newly-discovered MAC/manufacturer/
    /// OS diffs as "unchanged" and is silently dropped, leaving the screen
    /// stuck on "Unknown". The snapshot is used only if the row has since
    /// left the live list.
    private var device: DiscoveredDevice {
        var live = scanVM.devices.first { $0.id == snapshot.id } ?? snapshot
        live.securityFindings = securityVM.findings.filter { $0.deviceID == snapshot.id }
        return live
    }

    var body: some View {
        let device = self.device
        ScrollView {
            VStack(spacing: 16) {
                // Drawn in content, not as a system bar: the roots hide the bar, and a bar appearing on push shifts the layout.
                HStack {
                    Button { dismiss() } label: { Label("Back", systemImage: "chevron.left") }
                    Spacer()
                }
                CardView {
                    HStack(spacing: 16) {
                        Image(systemName: device.deviceIcon).font(.system(size: 40))
                            .foregroundColor(SecurityStatus.of(findings: device.securityFindings, settled: device.probesSettled, probed: device.wasProbed).color)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(device.hostname).font(.title2.bold())
                            Text(device.ipAddress).foregroundColor(.secondary)
                            if device.isOnLocalSubnet == false {
                                AppBadge(text: "Other network", color: AppColors.pending)
                                Text("Not on the network you are connected to, so it may not be reachable directly.")
                                    .font(.caption).foregroundColor(.secondary)
                            }
                            if let skip = device.paymentVendorSkip {
                                AppBadge(text: skip.badgeText, color: AppColors.pending)
                                Text(PaymentVendorSkip.detail).font(.caption).foregroundColor(.secondary)
                            }
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
                        if let note = device.macNote(vendorLookup: { OUIDatabase.shared.manufacturer(for: $0) }) {
                            Text(note).font(.caption).foregroundColor(.secondary)
                        }
                        row("Manufacturer", device.manufacturer ?? "Unknown")
                        if device.isApplianceMaker { AppBadge(text: "Appliance maker (vendor name is on the appliance list)", color: AppColors.pending) }
                        row("Inferred OS",  device.displayInferredOS  ?? "Unknown")
                        if let server = device.ssdpServer { row("Server header", server, selectable: true) }
                        row("Open Ports",   device.openPorts.isEmpty ? device.noOpenPortsText : device.openPorts.map { String($0) }.joined(separator: ", "))
                        if let skip = device.paymentVendorSkip {
                            Text(skip.note).font(.caption).foregroundColor(.secondary)
                        }
                    }
                }

                // Never empty: a device with no resolved list still lists the address shown in its header.
                let addresses = device.addresses.isEmpty ? [device.ipAddress] : device.addresses
                if !addresses.isEmpty {
                    CardView {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("Addresses").font(.headline)
                            Divider()
                            ForEach(addresses, id: \.self) { address in
                                row(address.contains(":") ? "IPv6" : "IPv4", address, selectable: true)
                            }
                        }
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
                                    if svc.port > 0 { Text("Advertised port \(String(svc.port))").font(.caption2).foregroundColor(.secondary) }
                                    if svc.serviceType == "_matterc._udp", let dt = svc.txtRecords["DT"], let name = BonjourTypeCatalog.matterDeviceTypeName(dt) {
                                        Text(verbatim: "Matter device type: \(name) (DT \(dt))").font(.caption2).foregroundColor(.secondary)
                                    }
                                    ForEach(svc.txtRecords.sorted(by: { $0.key < $1.key }), id: \.key) { key, value in
                                        Text(verbatim: "\(key): \(value)").font(.caption2).foregroundColor(.secondary)
                                    }
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
        .toolbar(.hidden, for: .navigationBar)
    }

    private func row(_ label: String, _ value: String, selectable: Bool = false) -> some View {
        // .firstTextBaseline, not the default .center: MAC/OS values can now
        // be long enough to wrap (a real MAC via arpTableLookup is 17
        // characters), and a wrapped 2-line value under center alignment
        // pulls the single-line label down to the vertical midpoint instead
        // of lining up with the value's first line.
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundColor(.secondary).font(.subheadline)
            Spacer()
            if selectable {
                Text(value).font(.subheadline.weight(.medium)).multilineTextAlignment(.trailing)
                    .textSelection(.enabled)
            } else {
                Text(value).font(.subheadline.weight(.medium)).multilineTextAlignment(.trailing)
            }
        }
    }
}
