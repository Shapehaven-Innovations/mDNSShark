// mDNSShark/Devices/BLEPeripheralRowView.swift
import SwiftUI
import DeviceFingerprint

/// One live Bluetooth peripheral in the Devices list.
/// `now` comes from the list's single TimelineView: a TimelineView inside every List cell kept the main thread busy, so the list could not scroll.
struct BLEPeripheralRowView: View {
    let peripheral: BLEPeripheral
    let now: Date
    /// Nil for a row that is already saved.
    var onAdd: (() -> Void)?

    var body: some View {
        let dim = peripheral.lifecycle(now: now) == .dim
        CardView {
            HStack(spacing: 12) {
                // Only the icon dims, so the text keeps full contrast.
                Image(systemName: peripheral.icon).font(.title3).foregroundColor(AppColors.info).frame(width: 28)
                    .opacity(dim ? Self.dimmedIconOpacity : 1)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(peripheral.displayName).font(.body.weight(.semibold)).lineLimit(1)
                        Image(systemName: BluetoothSymbol.name).font(.caption).foregroundColor(AppColors.info)
                            .accessibilityLabel("Bluetooth")
                    }
                    Text(Self.detailLine(company: peripheral.parsed.companyName, typeLabel: peripheral.typeLabel,
                                         rssi: peripheral.rssi, distance: peripheral.distance.label,
                                         lastSeenSeconds: dim ? max(0, Int(now.timeIntervalSince(peripheral.lastSeen))) : nil))
                        .font(.caption).foregroundColor(.secondary).lineLimit(2)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.caption).foregroundColor(.secondary).accessibilityHidden(true)
            }
        }
        .accessibilityElement(children: .combine)
        // Same action as the leading swipe, for rows reached some other way.
        .contextMenu {
            if let onAdd { Button("Add to devices", systemImage: "plus.circle", action: onAdd) }
        }
        .accessibilityActions {
            // The combined element hides the inner buttons from VoiceOver, so Add comes back as a named action.
            if let onAdd { Button("Add to devices", action: onAdd) }
        }
    }

    static let dimmedIconOpacity = 0.4

    /// "<company> · <type> · -86 dBm · Far", with "Last seen" replacing the proximity when the row is dimmed.
    static func detailLine(company: String?, typeLabel: String, rssi: Int, distance: String, lastSeenSeconds: Int?) -> String {
        let tail = lastSeenSeconds.map { "Last seen \($0)s ago" } ?? distance
        return "\(companyLine(company: company, typeLabel: typeLabel)) · \(rssi) dBm · \(tail)"
    }

    /// "<company> · <type>"; an unknown type is left out when a company is shown, and reads "Unknown type" alone.
    static func companyLine(company: String?, typeLabel: String) -> String {
        let typeKnown = typeLabel != BLEKind.unknown.label
        guard let company, !company.isEmpty else { return typeKnown ? typeLabel : "Unknown type" }
        return typeKnown ? "\(company) · \(typeLabel)" : company
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

    static let notSeenText = "Saved, not seen now"

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
                    Text(Self.notSeenText).font(.subheadline).foregroundColor(.secondary)
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
