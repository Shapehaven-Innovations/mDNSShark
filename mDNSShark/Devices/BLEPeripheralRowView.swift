// mDNSShark/Devices/BLEPeripheralRowView.swift
import SwiftUI
import DeviceFingerprint

/// One live Bluetooth peripheral in the Devices list.
struct BLEPeripheralRowView: View {
    let peripheral: BLEPeripheral
    let status: BLERelationshipText.Line
    var onAdd: (() -> Void)?
    var onOpenDevice: ((UUID) -> Void)?

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let dim = peripheral.lifecycle(now: context.date) == .dim
            CardView {
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 12) {
                        // Only the icon dims, so the text keeps full contrast.
                        Image(systemName: peripheral.icon).font(.title2).foregroundColor(AppColors.info).frame(width: 32)
                            .opacity(dim ? Self.dimmedIconOpacity : 1)
                            .accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 6) {
                                Text(peripheral.displayName).font(.headline).lineLimit(1)
                                Image(systemName: BluetoothSymbol.name).font(.caption).foregroundColor(AppColors.info)
                                    .accessibilityLabel("Bluetooth")
                            }
                            Text(Self.companyLine(company: peripheral.parsed.companyName, typeLabel: peripheral.typeLabel))
                                .font(.subheadline).foregroundColor(.secondary)
                            Text("\(peripheral.rssi) dBm · \(peripheral.distance.label)")
                                .font(.caption).foregroundColor(.secondary)
                            if dim {
                                Text("Last seen \(max(0, Int(context.date.timeIntervalSince(peripheral.lastSeen))))s ago")
                                    .font(.caption).foregroundColor(.secondary)
                            }
                        }
                        Spacer()
                        Image(systemName: "chevron.right").font(.caption).foregroundColor(.secondary).accessibilityHidden(true)
                    }
                    statusLine
                    if status.title == BLERelationshipText.notOnNetwork, let onAdd {
                        Button("Add to devices", action: onAdd).buttonStyle(.bordered).font(.subheadline)
                            .accessibilityHint("Keeps this Bluetooth device in your Devices list")
                    }
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityActions {
                // The combined element hides the inner buttons from VoiceOver, so they come back as named actions.
                if status.title == BLERelationshipText.notOnNetwork, let onAdd {
                    Button("Add to devices", action: onAdd)
                }
                if let deviceID = status.deviceID, let onOpenDevice {
                    Button("Open network device") { onOpenDevice(deviceID) }
                }
            }
        }
    }

    @ViewBuilder private var statusLine: some View {
        let label = HStack(alignment: .firstTextBaseline, spacing: 6) {
            if status.deviceID != nil {
                Image(systemName: "link.badge.plus").accessibilityHidden(true)
            }
            Text(status.title).font(.subheadline).multilineTextAlignment(.leading)
        }
        .foregroundColor(status.deviceID != nil ? AppColors.info : .secondary)

        if let deviceID = status.deviceID, let onOpenDevice {
            Button { onOpenDevice(deviceID) } label: { label }
                .buttonStyle(.plain)
                .accessibilityHint("Opens the network device")
        } else {
            label
        }
    }

    static let dimmedIconOpacity = 0.4

    /// "<company> · <type>", or the type alone when nothing names a company.
    static func companyLine(company: String?, typeLabel: String) -> String {
        guard let company, !company.isEmpty else { return typeLabel }
        return "\(company) · \(typeLabel)"
    }
}

/// A saved Bluetooth device that is not advertising nearby right now.
struct BLESavedDeviceRowView: View {
    let device: BLESavedDevice
    /// The other saved entries this one can be merged into.
    var mergeTargets: [BLESavedDevice] = []
    var onForget: () -> Void
    var onMerge: (UUID) -> Void
    @State private var confirmingForget = false

    var body: some View {
        CardView {
            HStack(spacing: 12) {
                // Only the icon dims, so the text keeps full contrast.
                Image(systemName: device.icon).font(.title2).foregroundColor(AppColors.info).frame(width: 32)
                    .opacity(BLEPeripheralRowView.dimmedIconOpacity)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(device.displayName).font(.headline).lineLimit(1)
                        Image(systemName: BluetoothSymbol.name).font(.caption).foregroundColor(AppColors.info)
                            .accessibilityLabel("Bluetooth")
                    }
                    Text(BLEPeripheralRowView.companyLine(company: device.companyName, typeLabel: device.typeLabel))
                        .font(.subheadline).foregroundColor(.secondary)
                    Text(BLERelationshipText.savedNotSeen).font(.subheadline).foregroundColor(.secondary)
                }
                Spacer()
            }
        }
        .accessibilityElement(children: .combine)
        .contextMenu {
            if !mergeTargets.isEmpty {
                Menu("Merge into\u{2026}") {
                    ForEach(mergeTargets) { entry in
                        Button(entry.displayName) { onMerge(entry.id) }
                    }
                }
            }
            Button("Forget", role: .destructive) { confirmingForget = true }
        }
        .accessibilityActions {
            // The context menu is hard to reach with VoiceOver, so each merge target is its own action.
            ForEach(mergeTargets) { entry in
                Button(Self.mergeActionName(entry.displayName)) { onMerge(entry.id) }
            }
            Button("Forget") { confirmingForget = true }
        }
        .confirmationDialog(Self.forgetConfirmation(name: device.displayName), isPresented: $confirmingForget, titleVisibility: .visible) {
            Button("Forget", role: .destructive, action: onForget)
            Button("Cancel", role: .cancel) {}
        }
    }

    static func mergeActionName(_ name: String) -> String { "Merge into \(name)" }

    /// Shared with the peripheral detail screen.
    static func forgetConfirmation(name: String) -> String {
        "Forget \(name)? It is removed from Devices. Its notes are deleted."
    }
}
