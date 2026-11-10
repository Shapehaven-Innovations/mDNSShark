// mDNSShark/Devices/BLEPeripheralDetailView.swift
import SwiftUI
import DeviceFingerprint

/// Detail for one Bluetooth peripheral, re-read from `BluetoothViewModel` on every body pass so it stays live.
struct BLEPeripheralDetailView: View {
    @EnvironmentObject var bluetoothVM: BluetoothViewModel
    @Environment(\.dismiss) private var dismiss
    let peripheralID: UUID
    /// The last live row seen, used only once the row has left the live list.
    @State private var lastKnown: BLEPeripheral?
    @State private var confirmingRead = false
    @State private var confirmingForget = false

    init(peripheralID: UUID) { self.peripheralID = peripheralID }

    private var live: BLEPeripheral? { bluetoothVM.peripheral(id: peripheralID) }

    var body: some View {
        let live = self.live
        let peripheral = live ?? lastKnown
        ScrollView {
            VStack(spacing: 16) {
                // Drawn in content like DeviceDetailView, because the roots hide the navigation bar.
                HStack {
                    Button { dismiss() } label: { Label("Back", systemImage: "chevron.left") }
                    Spacer()
                }
                if let p = peripheral {
                    header(p, isLive: live != nil)
                    BluetoothCardView(peripheral: p, onReadInfo: live != nil ? { confirmingRead = true } : nil)
                    .confirmationDialog(Self.readConfirmation(name: p.displayName), isPresented: $confirmingRead, titleVisibility: .visible) {
                        Button("Read device info") { Task { await bluetoothVM.readDeviceInfo(p.id) } }
                        Button("Cancel", role: .cancel) {}
                    }
                } else {
                    CardView {
                        Text("This Bluetooth device is no longer nearby.").foregroundColor(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
            .padding(.horizontal).padding(.vertical, 8)
        }
        .toolbar(.hidden, for: .navigationBar)
        .onChange(of: live, initial: true) { _, row in if let row { lastKnown = row } }
    }

    @ViewBuilder private func header(_ p: BLEPeripheral, isLive: Bool) -> some View {
        CardView {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 16) {
                    Image(systemName: p.icon).font(.system(size: 40)).foregroundColor(AppColors.info)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(p.displayName).font(.title2.bold())
                        if let company = p.parsed.companyName { Text(company).foregroundColor(.secondary) }
                        Text(p.typeLabel).font(.caption).foregroundColor(.secondary)
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            if p.lifecycle(now: context.date) != .live || !isLive {
                                Text("Last seen \(max(0, Int(context.date.timeIntervalSince(p.lastSeen)))) s ago")
                                    .font(.caption).foregroundColor(.secondary)
                            }
                        }
                    }
                    Spacer()
                }
                .accessibilityElement(children: .combine)
                if let savedID = p.savedID {
                    savedControls(savedID, isLive: isLive)
                }
            }
        }
    }

    @ViewBuilder private func savedControls(_ savedID: UUID, isLive: Bool) -> some View {
        let others = bluetoothVM.saved.filter { $0.id != savedID }
        HStack(spacing: 12) {
            AppBadge(text: "Saved", color: AppColors.info)
                .accessibilityLabel("Saved in Devices")
            Spacer()
            if isLive, !others.isEmpty {
                Menu("Merge into\u{2026}") {
                    ForEach(others) { entry in
                        Button(entry.displayName) { bluetoothVM.mergeSaved(savedID, into: entry.id) }
                    }
                }
                .accessibilityHint("Combines this saved entry with another saved Bluetooth device")
            }
            Button("Forget", role: .destructive) { confirmingForget = true }
                .accessibilityHint("Removes this Bluetooth device from Devices")
        }
        .font(.subheadline)
        .confirmationDialog(BLESavedDeviceRowView.forgetConfirmation(name: bluetoothVM.saved.first { $0.id == savedID }?.displayName ?? "this device"),
                            isPresented: $confirmingForget, titleVisibility: .visible) {
            Button("Forget", role: .destructive) {
                bluetoothVM.forgetSaved(savedID)
                // The kept copy must not bring back a Saved badge for an entry that is gone.
                if lastKnown?.savedID == savedID { lastKnown?.savedID = nil }
            }
            Button("Cancel", role: .cancel) {}
        }
    }

    /// The confirmation text for the one user-started connection.
    nonisolated static func readConfirmation(name: String) -> String {
        "mDNSShark will connect to \(name) once, read its Device Information and Battery services, listen for one heart rate measurement if it has a Heart Rate service, and disconnect within 5 seconds. Nothing is written to the device."
    }
}
