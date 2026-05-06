// mDNSShark/Topology/DevicePickerSheet.swift
import SwiftUI

struct DevicePickerSheet: View {
    @Binding var pinnedIPsRaw: String
    let allDevices: [DiscoveredDevice]
    let findings: [SecurityFinding]

    @Environment(\.presentationMode) private var presentationMode
    @State private var searchText = ""

    private var pinnedIPs: Set<String> {
        Set(pinnedIPsRaw.split(separator: ",").map(String.init).filter { !$0.isEmpty })
    }

    private func rank(_ d: DiscoveredDevice) -> Int {
        if d.isGateway { return 0 }
        let worst = findings.filter { $0.deviceID == d.id }.map(\.severity).max()
        if worst == .critical { return 1 }
        if worst == .warning  { return 2 }
        switch d.deviceType {
        case .apple:    return 3
        case .tv:       return 4
        case .printer:  return 5
        case .computer: return 6
        default:        return 7
        }
    }

    private var sortedDevices: [DiscoveredDevice] {
        let pinned    = allDevices.filter {  pinnedIPs.contains($0.ipAddress) }
        let nonPinned = allDevices.filter { !pinnedIPs.contains($0.ipAddress) }
        let sorted    = nonPinned.sorted { a, b in
            let ra = rank(a), rb = rank(b)
            return ra != rb ? ra < rb : a.ipAddress < b.ipAddress
        }
        return pinned + sorted
    }

    private var filteredDevices: [DiscoveredDevice] {
        guard !searchText.isEmpty else { return sortedDevices }
        let q = searchText.lowercased()
        return sortedDevices.filter {
            $0.hostname.lowercased().contains(q) || $0.ipAddress.lowercased().contains(q)
        }
    }

    private func toggle(_ ip: String) {
        var ips = pinnedIPs
        if ips.contains(ip) { ips.remove(ip) } else { ips.insert(ip) }
        pinnedIPsRaw = ips.joined(separator: ",")
    }

    private func typeLabel(_ type: DeviceType) -> String {
        switch type {
        case .router:   return "Router"
        case .apple:    return "Apple"
        case .computer: return "Computer"
        case .printer:  return "Printer"
        case .tv:       return "TV"
        case .unknown:  return "Unknown"
        }
    }

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                HStack {
                    Image(systemName: "magnifyingglass").foregroundColor(.secondary)
                    TextField("Hostname or IP", text: $searchText)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                }
                .padding(10)
                .background(Color(.secondarySystemBackground))
                .cornerRadius(10)
                .padding(.horizontal)
                .padding(.vertical, 8)

                if !pinnedIPsRaw.isEmpty {
                    HStack {
                        Spacer()
                        Button("Clear All") { pinnedIPsRaw = "" }
                            .foregroundColor(.red)
                            .font(.subheadline)
                    }
                    .padding(.horizontal)
                    .padding(.bottom, 6)
                }

                List(filteredDevices) { device in
                    Button { toggle(device.ipAddress) } label: {
                        HStack(spacing: 12) {
                            Image(systemName: device.deviceIcon)
                                .frame(width: 24)
                                .foregroundColor(AppColors.info)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(device.hostname)
                                    .font(.subheadline.weight(.medium))
                                    .foregroundColor(.primary)
                                Text("\(device.ipAddress) · \(typeLabel(device.deviceType))")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            Spacer()
                            if pinnedIPs.contains(device.ipAddress) {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(AppColors.secure)
                            }
                        }
                    }
                    .buttonStyle(.plain)
                }
            }
            .navigationTitle("Add Devices")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { presentationMode.wrappedValue.dismiss() }
                }
            }
        }
    }
}
