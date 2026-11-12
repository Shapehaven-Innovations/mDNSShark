// mDNSShark/Devices/DeviceDetailView.swift
import SwiftUI
import DeviceFingerprint

struct DeviceDetailView: View {
    @EnvironmentObject var scanVM: NetworkScanViewModel
    @EnvironmentObject var securityVM: SecurityViewModel
    @Environment(\.dismiss) private var dismiss
    // Navigation-time snapshot. Only a fallback; see `device` below.
    private let snapshot: DiscoveredDevice
    @State private var confirmingProbe = false

    init(device: DiscoveredDevice) {
        snapshot = device
    }

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
                            .foregroundColor(SecurityStatus.of(findings: device.securityFindings, settled: device.probesSettled).color)
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
                        DetailRow(label: "MAC Address", value: device.macAddress ?? "Unknown")
                        if let note = device.macNote(vendorLookup: { OUIDatabase.shared.manufacturer(for: $0) }) {
                            Text(note).font(.caption).foregroundColor(.secondary)
                        }
                        DetailRow(label: "Manufacturer", value: device.manufacturer ?? "Unknown")
                        if device.isApplianceMaker { AppBadge(text: "Appliance maker (vendor name is on the appliance list)", color: AppColors.pending) }
                        DetailRow(label: "Inferred OS", value: device.displayInferredOS ?? "Unknown")
                        if let server = device.ssdpServer { DetailRow(label: "Server header", value: server, selectable: true) }
                        DetailRow(label: "Open Ports", value: device.openPorts.isEmpty ? "None" : device.openPorts.map { String($0) }.joined(separator: ", "))
                        if let skip = device.paymentVendorSkip {
                            Text(skip.note(offNetwork: device.isOnLocalSubnet == false)).font(.caption).foregroundColor(.secondary)
                        }
                    }
                }

                CardView {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Network").font(.headline)
                        Divider()
                        ForEach(device.networkNote(ownCIDRs: scanVM.ownSubnetCIDRs), id: \.self) { line in
                            Text(verbatim: line).font(.subheadline).textSelection(.enabled)
                        }
                        if device.isOnLocalSubnet == false, !device.probeRequested, device.paymentVendorSkip == nil {
                            if let skip = txtMACSkip {
                                Text("Probe request not available: \(skip.vendor) makes payment or roadside equipment (from the MAC in its TXT record)")
                                    .font(.caption).foregroundColor(.secondary)
                            } else {
                                Button("Probe this device") { confirmingProbe = true }
                                    .buttonStyle(.bordered)
                            }
                        }
                    }
                }
                .confirmationDialog(Self.probeConfirmation(ip: device.ipAddress, phoneCIDRs: scanVM.ownSubnetCIDRs),
                                    isPresented: $confirmingProbe, titleVisibility: .visible) {
                    Button("Probe") { scanVM.probeAnyway(ip: device.ipAddress) }
                    Button("Cancel", role: .cancel) {}
                }

                // Never empty: a device with no resolved list still lists the address shown in its header.
                let addresses = device.addresses.isEmpty ? [device.ipAddress] : device.addresses
                if !addresses.isEmpty {
                    CardView {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("Addresses").font(.headline)
                            Divider()
                            ForEach(addresses, id: \.self) { address in
                                DetailRow(label: address.contains(":") ? "IPv6" : "IPv4", value: address, selectable: true)
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

    /// The payment or roadside skip implied by the MAC in the device's TXT record, if any.
    private var txtMACSkip: PaymentVendorSkip? {
        device.macAddress.flatMap { PaymentVendorGate.vendorSkip(forMAC: $0, sentTrigger: false, vendorLookup: OUIDatabase.shared.manufacturer(for:)) }
    }

    /// The confirmation text, with the literal address and this phone's CIDRs.
    static func probeConfirmation(ip: String, phoneCIDRs: [String]) -> String {
        "\(ip) is outside \(phoneCIDRs.joined(separator: ", ")). mDNSShark will send its standard probes (about 50 packets) to this one address through your router. The payment-terminal check cannot run across a router. Only probe networks you are allowed to test."
    }
}
