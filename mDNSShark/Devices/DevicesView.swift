// mDNSShark/Devices/DevicesView.swift
import SwiftUI
import DeviceFingerprint

struct DevicesView: View {
    @EnvironmentObject var scanVM: NetworkScanViewModel
    @EnvironmentObject var securityVM: SecurityViewModel
    @EnvironmentObject var deepLinks: DeepLinkRouter
    @EnvironmentObject var bluetoothVM: BluetoothViewModel
    @EnvironmentObject var coordinator: AppCoordinator
    @State private var filter: DevicesFilter = .lan

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
                        // The one tick for every row: it ages the rows and drops those that expire while nothing else publishes.
                        TimelineView(.periodic(from: .now, by: 5)) { context in
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
                                        saved: bluetoothVM.saved, now: now)
        VStack(spacing: 12) {
            Picker("Show", selection: $filter) {
                ForEach(DevicesFilter.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .accessibilityLabel("Device filter")

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
                        ForEach(section.rows) { row in rowView(row, now: now) }
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

    @ViewBuilder private func rowView(_ row: DevicesListPlan.Row, now: Date) -> some View {
        switch row {
        case .lan(let device):
            let findings = securityVM.findings.filter { $0.deviceID == device.id }
            let badgeColor = SecurityStatus.of(findings: findings, settled: device.probesSettled).color
            NavigationLink(destination: DeviceDetailView(device: device)) {
                DeviceCardView(device: device, issueCount: findings.count, badgeColor: badgeColor)
            }
            .buttonStyle(.plain)
        case .peripheral(let p):
            NavigationLink(destination: BLEPeripheralDetailView(peripheralID: p.id)) {
                BLEPeripheralRowView(peripheral: p, now: now, onAdd: p.savedID == nil ? { bluetoothVM.addToDevices(p.id) } : nil)
            }
            .buttonStyle(.plain)
        case .saved(let entry):
            savedRow(entry)
        }
    }

    private func savedRow(_ entry: BLESavedDevice) -> some View {
        BLESavedDeviceRowView(
            device: entry,
            mergeTargets: bluetoothVM.saved.filter { $0.id != entry.id },
            onForget: { bluetoothVM.forgetSaved(entry.id) },
            onMerge: { target in bluetoothVM.mergeSaved(entry.id, into: target) })
    }

    // MARK: Bluetooth list, status line and prompts

    /// The Bluetooth filter is a List so rows can swipe: right adds to Devices, left removes from the list.
    @ViewBuilder private var bluetoothList: some View {
        // The one tick for every row; a TimelineView inside each List cell kept the main thread busy, so the list could not scroll.
        TimelineView(.periodic(from: .now, by: 5)) { context in
            let plan = DevicesListPlan.make(filter: .bluetooth, devices: scanVM.devices, peripherals: bluetoothVM.peripherals,
                                            saved: bluetoothVM.saved, now: context.date)
            let state = accessState
            List {
                Picker("Show", selection: $filter) {
                    ForEach(DevicesFilter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .accessibilityLabel("Device filter")
                .plainListRow()

                if state == .ready {
                    scanStatusLine(now: context.date).plainListRow()
                } else {
                    BluetoothAccessView(state: state, onAllow: { bluetoothVM.allowAndScan() }).plainListRow()
                }

                if plan.isEmpty {
                    emptyState.plainListRow()
                } else {
                    ForEach(plan.sections) { section in
                        if !section.rows.isEmpty {
                            Section {
                                ForEach(section.rows) { row in bluetoothRow(row, now: context.date) }
                            } header: {
                                if !section.title.isEmpty {
                                    Text(section.title).font(.headline).foregroundColor(.primary).textCase(nil)
                                        .accessibilityAddTraits(.isHeader)
                                }
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
            .animation(.default, value: plan.sections.flatMap(\.rows).map(\.id))
        }
    }

    @ViewBuilder private func bluetoothRow(_ row: DevicesListPlan.Row, now: Date) -> some View {
        switch row {
        case .peripheral(let p):
            let canAdd = p.savedID == nil
            ZStack {
                BLEPeripheralRowView(peripheral: p, now: now, onAdd: canAdd ? { bluetoothVM.addToDevices(p.id) } : nil)
                // The system chevron is hidden; the row draws its own.
                NavigationLink(destination: BLEPeripheralDetailView(peripheralID: p.id)) { EmptyView() }.opacity(0)
            }
            .plainListRow()
            .swipeActions(edge: .leading, allowsFullSwipe: true) {
                if canAdd {
                    Button { bluetoothVM.addToDevices(p.id) } label: { Label("Add", systemImage: "plus.circle") }
                        .tint(AppColors.info)
                }
            }
            .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                if canAdd {
                    Button(role: .destructive) { bluetoothVM.removeFromList(p.id) } label: { Label("Remove", systemImage: "trash") }
                }
            }
        case .saved(let entry):
            savedRow(entry).plainListRow()
        case .lan:
            EmptyView()
        }
    }

    /// A spinner with the running scan's count; after a scan, the listed count and the scan time. Nothing before the first scan.
    @ViewBuilder private func scanStatusLine(now: Date) -> some View {
        if bluetoothVM.isScanning {
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text(Self.scanningText(found: bluetoothVM.seenThisScanCount))
            }
            .font(.subheadline).foregroundColor(.secondary)
            .accessibilityElement(children: .combine)
        } else if let summary = bluetoothVM.lastScanSummary {
            let nearby = BluetoothViewModel.nearbyCount(peripherals: bluetoothVM.peripherals, now: now)
            // Zero is said by the empty state instead.
            if nearby > 0 {
                Text(Self.idleText(nearby: nearby, scannedAt: summary.scannedAt))
                    .font(.subheadline).foregroundColor(.secondary)
            }
        }
    }

    /// Counts only rows heard in this scan, so rows kept from an earlier scan are not "found" again.
    static func scanningText(found: Int) -> String { "Scanning · \(found) found" }

    static func idleText(nearby: Int, scannedAt: Date) -> String {
        "\(nearby) nearby · Last scan \(scannedAt.formatted(date: .omitted, time: .shortened))"
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

    @ViewBuilder private var emptyState: some View {
        switch filter {
        case .lan:
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
