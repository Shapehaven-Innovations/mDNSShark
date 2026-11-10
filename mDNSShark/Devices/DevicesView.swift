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
            Group {
                if filter == .bluetooth {
                    bluetoothList
                } else {
                    ScrollView {
                        // The periodic tick drops rows that expire while nothing else publishes.
                        TimelineView(.periodic(from: .now, by: 15)) { context in
                            content(now: context.date)
                        }
                    }
                }
            }
            .overlay(alignment: .bottomTrailing) {
                if filter == .bluetooth, accessState == .ready { scanButton }
            }
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

            if filter == .all, state == .undetermined, !bluetoothVM.hasScannedThisSession {
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

            if !scanVM.unattachedServices.isEmpty {
                UnattachedServicesSection(services: scanVM.unattachedServices)
                    .padding(.top, 8)
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
            NavigationLink(destination: peripheralDestination(p)) { rowView }
                .buttonStyle(.plain)
        case .saved(let entry):
            savedRow(entry)
        }
    }

    /// A suggested row opens the LAN device it is suggested for, at its Bluetooth card.
    @ViewBuilder private func peripheralDestination(_ p: BLEPeripheral) -> some View {
        if let deviceID = bluetoothVM.matches.suggestion(forPeripheral: p.id)?.deviceID,
           let device = scanVM.devices.first(where: { $0.id == deviceID }) {
            DeviceDetailView(device: device, scrollTo: .bluetooth)
        } else {
            BLEPeripheralDetailView(peripheralID: p.id)
        }
    }

    private func savedRow(_ entry: BLESavedDevice) -> some View {
        BLESavedDeviceRowView(
            device: entry,
            mergeTargets: bluetoothVM.saved.filter { $0.id != entry.id },
            onForget: { bluetoothVM.forgetSaved(entry.id) },
            onMerge: { target in bluetoothVM.mergeSaved(entry.id, into: target) })
    }

    private func status(for p: BLEPeripheral) -> BLERelationshipText.Line {
        let devices = scanVM.devices
        return BLERelationshipText.forPeripheral(
            peripheralID: p.id, table: bluetoothVM.matches, isSaved: p.savedID != nil,
            deviceName: { id in devices.first { $0.id == id }?.hostname ?? "Unknown device" },
            deviceIP: { id in devices.first { $0.id == id }?.ipAddress })
    }

    // MARK: Bluetooth header and prompts

    /// The Bluetooth filter is a List so rows can swipe: right adds to Devices, left removes from the list.
    @ViewBuilder private var bluetoothList: some View {
        // The periodic tick drops rows that expire while nothing else publishes.
        TimelineView(.periodic(from: .now, by: 15)) { context in
            let plan = DevicesListPlan.make(filter: .bluetooth, devices: scanVM.devices, peripherals: bluetoothVM.peripherals,
                                            saved: bluetoothVM.saved, matches: bluetoothVM.matches, now: context.date)
            let state = accessState
            List {
                Picker("Show", selection: $filter) {
                    ForEach(DevicesFilter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .accessibilityLabel("Device filter")
                .plainListRow()

                if state == .ready {
                    if bluetoothVM.isScanning { scanStatusLine.plainListRow() }
                } else {
                    BluetoothAccessView(state: state, onAllow: { bluetoothVM.allowAndScan() }).plainListRow()
                }

                if plan.isEmpty {
                    emptyState.plainListRow()
                } else {
                    ForEach(plan.sections) { section in
                        if !section.rows.isEmpty {
                            Section {
                                ForEach(section.rows) { row in bluetoothRow(row) }
                            } header: {
                                Text(section.title).font(.headline).foregroundColor(.primary).textCase(nil)
                                    .accessibilityAddTraits(.isHeader)
                            }
                            .listSectionSeparator(.hidden)
                        }
                    }
                }

                if state == .ready {
                    // Draws only the footer in the ready state, so the privacy note shows in every state.
                    BluetoothAccessView(state: .ready, onAllow: {}).plainListRow()
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            .contentMargins(.bottom, 88, for: .scrollContent)
            .refreshable { _ = bluetoothVM.refreshFromPull() }
            .animation(.default, value: plan.sections.flatMap(\.rows).map(\.id))
        }
    }

    @ViewBuilder private func bluetoothRow(_ row: DevicesListPlan.Row) -> some View {
        switch row {
        case .peripheral(let p):
            let line = status(for: p)
            let canAdd = p.savedID == nil && line.title == BLERelationshipText.notOnNetwork
            ZStack {
                BLEPeripheralRowView(
                    peripheral: p, status: line,
                    onAdd: canAdd ? { bluetoothVM.addToDevices(p.id) } : nil,
                    onOpenDevice: { id in if scanVM.devices.contains(where: { $0.id == id }) { openBluetoothDeviceID = id } })
                // The system chevron is hidden; the row draws its own.
                NavigationLink(destination: peripheralDestination(p)) { EmptyView() }.opacity(0)
            }
            .plainListRow()
            .swipeActions(edge: .leading, allowsFullSwipe: true) {
                if canAdd {
                    Button { bluetoothVM.addToDevices(p.id) } label: { Label("Add", systemImage: "plus.circle") }
                        .tint(AppColors.info)
                }
            }
            .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                if p.savedID == nil {
                    Button(role: .destructive) { bluetoothVM.removeFromList(p.id) } label: { Label("Remove", systemImage: "trash") }
                }
            }
        case .saved(let entry):
            savedRow(entry).plainListRow()
        case .lan:
            EmptyView()
        }
    }

    /// Counts only rows heard in this scan, so rows kept from an earlier scan are not "found" again.
    private var scanStatusLine: some View {
        Text("Scanning nearby\u{2026} Bluetooth LE · \(bluetoothVM.seenThisScanCount) found · \(bluetoothVM.seenThisScanSuggestedCount) suggested")
            .font(.caption).foregroundColor(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityElement(children: .combine)
    }

    /// Floating scan control: starts a 25 second scan, or stops the running one.
    private var scanButton: some View {
        let scanning = bluetoothVM.isScanning
        return Button {
            if scanning { bluetoothVM.stopScan(reason: .user) } else { bluetoothVM.startScanIfAuthorized() }
        } label: {
            ZStack {
                if scanning {
                    ProgressView().tint(.white).scaleEffect(1.5)
                    Image(systemName: "stop.fill").font(.caption.weight(.bold))
                } else {
                    Image(systemName: BluetoothSymbol.name).font(.title2.weight(.semibold))
                }
            }
            .foregroundColor(.white)
            .frame(width: 56, height: 56)
            .background(Circle().fill(AppColors.info))
            .shadow(color: .black.opacity(0.25), radius: 6, y: 3)
        }
        .padding(.trailing, 20).padding(.bottom, 16)
        .sensoryFeedback(.impact, trigger: scanning)
        .accessibilityLabel(scanning ? "Stop Bluetooth scan" : "Scan Bluetooth")
        .accessibilityValue(scanning ? "Scanning, \(bluetoothVM.seenThisScanCount) found" : "")
        .accessibilityHint(scanning ? "" : "Listens for nearby Bluetooth advertisements for 25 seconds")
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
                Text(bluetoothVM.hasScannedThisSession ? "No Bluetooth devices nearby." : "Tap the Bluetooth button to list nearby devices.")
                    .foregroundColor(.secondary).padding(20)
            }
        }
    }
}

private extension View {
    /// A List row drawn like the card layout: no separator, no row background, card spacing.
    func plainListRow() -> some View {
        listRowSeparator(.hidden)
            .listRowBackground(Color.clear)
            .listRowInsets(EdgeInsets(top: 6, leading: 16, bottom: 6, trailing: 16))
    }
}
