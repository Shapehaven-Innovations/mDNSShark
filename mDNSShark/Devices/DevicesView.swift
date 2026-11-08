// mDNSShark/Devices/DevicesView.swift
import SwiftUI
import DeviceFingerprint

struct DevicesView: View {
    @EnvironmentObject var scanVM: NetworkScanViewModel
    @EnvironmentObject var securityVM: SecurityViewModel
    @EnvironmentObject var deepLinks: DeepLinkRouter
    @EnvironmentObject var bluetoothVM: BluetoothViewModel
    @EnvironmentObject var coordinator: AppCoordinator
    @State private var filter: DevicesFilter = .all
    /// A LAN device opened from a Bluetooth status line, shown scrolled to its Bluetooth card.
    @State private var openBluetoothDeviceID: UUID?

    private var accessState: BluetoothAccessState {
        BluetoothAccessState.from(authorization: bluetoothVM.authorization, power: bluetoothVM.powerState)
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                // The periodic tick drops rows that expire while nothing else publishes.
                TimelineView(.periodic(from: .now, by: 15)) { context in
                    content(now: context.date)
                }
            }
            .modifier(BluetoothPullToRefresh(isEnabled: filter == .bluetooth) { _ = bluetoothVM.refreshFromPull() })
            .navigationDestination(item: $deepLinks.deviceLinkID) { id in
                if let device = scanVM.devices.first(where: { $0.id == id }) { DeviceDetailView(device: device) }
            }
            .navigationDestination(item: $openBluetoothDeviceID) { id in
                if let device = scanVM.devices.first(where: { $0.id == id }) { DeviceDetailView(device: device, scrollTo: .bluetooth) }
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar(.hidden, for: .navigationBar)
        }
        .onChange(of: coordinator.devicesFilterRequest, initial: true) { _, request in
            guard let request else { return }
            filter = request
            coordinator.devicesFilterRequest = nil
        }
    }

    @ViewBuilder private func content(now: Date) -> some View {
        let plan = DevicesListPlan.make(filter: filter, devices: scanVM.devices, peripherals: bluetoothVM.peripherals,
                                        saved: bluetoothVM.saved, matches: bluetoothVM.matches, now: now)
        let state = accessState
        VStack(spacing: 12) {
            Picker("Show", selection: $filter) {
                ForEach(DevicesFilter.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .accessibilityLabel("Device filter")

            if filter == .bluetooth {
                if state == .ready { bluetoothHeader }
                if state != .ready { BluetoothAccessView(state: state, onAllow: { bluetoothVM.allowAndScan() }) }
            } else if filter == .all, state == .undetermined, !bluetoothVM.hasScannedThisSession {
                allBluetoothPrompt
            }

            if plan.isEmpty {
                emptyState
            } else {
                ForEach(plan.sections) { section in
                    if !section.rows.isEmpty {
                        if !section.title.isEmpty {
                            Text(section.title).font(.headline).frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.top, 4)
                                .accessibilityAddTraits(.isHeader)
                        }
                        ForEach(section.rows) { row in rowView(row) }
                    }
                }
            }

            if filter != .bluetooth, !scanVM.unattachedServices.isEmpty {
                UnattachedServicesSection(services: scanVM.unattachedServices)
                    .padding(.top, 8)
            }
            if filter == .bluetooth, state == .ready {
                // Draws only the footer in the ready state, so the privacy note shows in every state.
                BluetoothAccessView(state: .ready, onAllow: {})
            }
        }
        .padding(.horizontal).padding(.top, 8)
        .animation(.default, value: plan.sections.flatMap(\.rows).map(\.id))
    }

    // MARK: Rows

    @ViewBuilder private func rowView(_ row: DevicesListPlan.Row) -> some View {
        switch row {
        case .lan(let device, let suggested):
            let findings = securityVM.findings.filter { $0.deviceID == device.id }
            let badgeColor = SecurityStatus.of(findings: findings, settled: device.probesSettled, probed: device.wasProbed).color
            NavigationLink(destination: DeviceDetailView(device: device)) {
                DeviceCardView(device: device, issueCount: findings.count, badgeColor: badgeColor, bluetoothSuggested: suggested)
            }
            .buttonStyle(.plain)
        case .peripheral(let p):
            let rowView = BLEPeripheralRowView(
                peripheral: p, status: status(for: p),
                onAdd: p.savedID == nil ? { bluetoothVM.addToDevices(p.id) } : nil,
                onOpenDevice: { id in if scanVM.devices.contains(where: { $0.id == id }) { openBluetoothDeviceID = id } })
            // A suggested row opens the LAN device it is suggested for, at its Bluetooth card.
            if let deviceID = bluetoothVM.matches.suggestion(forPeripheral: p.id)?.deviceID,
               let device = scanVM.devices.first(where: { $0.id == deviceID }) {
                NavigationLink(destination: DeviceDetailView(device: device, scrollTo: .bluetooth)) { rowView }
                    .buttonStyle(.plain)
            } else {
                NavigationLink(destination: BLEPeripheralDetailView(peripheralID: p.id)) { rowView }
                    .buttonStyle(.plain)
            }
        case .saved(let entry):
            BLESavedDeviceRowView(
                device: entry,
                mergeTargets: bluetoothVM.saved.filter { $0.id != entry.id },
                onForget: { bluetoothVM.forgetSaved(entry.id) },
                onMerge: { target in bluetoothVM.mergeSaved(entry.id, into: target) })
        }
    }

    private func status(for p: BLEPeripheral) -> BLERelationshipText.Line {
        let devices = scanVM.devices
        return BLERelationshipText.forPeripheral(
            peripheralID: p.id, table: bluetoothVM.matches, isSaved: p.savedID != nil,
            deviceName: { id in devices.first { $0.id == id }?.hostname ?? "Unknown device" },
            deviceIP: { id in devices.first { $0.id == id }?.ipAddress })
    }

    // MARK: Bluetooth header and prompts

    @ViewBuilder private var bluetoothHeader: some View {
        if bluetoothVM.isScanning {
            // Counts only rows heard in this scan, so rows kept from an earlier scan are not "found" again.
            HStack(spacing: 8) {
                ProgressView()
                Text("Scanning nearby\u{2026} Bluetooth LE · \(bluetoothVM.seenThisScanCount) found · \(bluetoothVM.seenThisScanSuggestedCount) suggested")
                    .font(.caption).foregroundColor(.secondary)
                Spacer()
                Button { bluetoothVM.stopScan(reason: .user) } label: {
                    Text("Stop").frame(minWidth: 44, minHeight: 44).contentShape(Rectangle())
                }
                .font(.caption)
            }
            .accessibilityElement(children: .combine)
        } else {
            HStack {
                Button {
                    bluetoothVM.startScanIfAuthorized()
                } label: {
                    Label("Scan Bluetooth", systemImage: BluetoothSymbol.name)
                }
                .buttonStyle(.bordered)
                .accessibilityHint("Listens for nearby Bluetooth advertisements for 25 seconds")
                Spacer()
            }
        }
    }

    private var allBluetoothPrompt: some View {
        Button { filter = .bluetooth } label: {
            HStack(spacing: 6) {
                Image(systemName: BluetoothSymbol.name).foregroundColor(AppColors.info).accessibilityHidden(true)
                Text("Nearby Bluetooth devices are not listed yet.").font(.caption).foregroundColor(.secondary)
                Spacer()
                Text("Set up").font(.caption)
            }
            .frame(minHeight: 44)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityHint("Shows the Bluetooth filter, where you can allow Bluetooth")
    }

    @ViewBuilder private var emptyState: some View {
        switch filter {
        case .all, .lan:
            VStack(spacing: 12) {
                Image(systemName: "magnifyingglass").font(.system(size: 48)).foregroundColor(.secondary)
                Text("No devices discovered yet.").foregroundColor(.secondary)
            }.padding(scanVM.unattachedServices.isEmpty ? 40 : 20)
        case .bluetooth:
            if accessState == .ready, !bluetoothVM.isScanning {
                Text(bluetoothVM.hasScannedThisSession ? "No Bluetooth devices nearby." : "Tap Scan Bluetooth to list nearby devices.")
                    .foregroundColor(.secondary).padding(20)
            }
        }
    }
}

/// Pull to refresh for the Bluetooth filter only; All and LAN keep a plain scroll view.
private struct BluetoothPullToRefresh: ViewModifier {
    let isEnabled: Bool
    let action: @MainActor () -> Void

    func body(content: Content) -> some View {
        if isEnabled {
            // The scan runs on after the spinner ends; its progress shows in the Bluetooth header.
            content.refreshable { action() }
        } else {
            content
        }
    }
}
