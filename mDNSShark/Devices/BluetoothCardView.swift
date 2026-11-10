// mDNSShark/Devices/BluetoothCardView.swift
import SwiftUI
import DeviceFingerprint

/// The Bluetooth card on both detail screens. With no peripheral it draws only the heading and relationship lines.
struct BluetoothCardView: View {
    /// A peripheral the LAN-side card lists as a link below the relationship lines.
    struct PeripheralLink: Identifiable, Equatable {
        let id: UUID
        let name: String
    }

    let peripheral: BLEPeripheral?
    let relationship: [BLERelationshipText.Line]
    var onOpenDevice: ((UUID) -> Void)? = nil
    var onOpenPeripheral: ((UUID) -> Void)? = nil
    var onReadInfo: (() -> Void)? = nil
    var peripheralLinks: [PeripheralLink] = []

    static let inferredCaption = "inferred, not confirmed"

    var body: some View {
        CardView {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 6) {
                    Image(systemName: BluetoothSymbol.name).foregroundColor(AppColors.info).accessibilityHidden(true)
                    Text("Bluetooth")
                }
                .font(.headline)
                .accessibilityAddTraits(.isHeader)
                Divider()
                relationshipSection
                if let p = peripheral {
                    Divider()
                    facts(p)
                    Divider()
                    inferred(p)
                    Divider()
                    deviceInformation(p)
                }
            }
        }
    }

    // MARK: Relationship

    @ViewBuilder private var relationshipSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(BLERelationshipText.heading).font(.subheadline).foregroundColor(.secondary)
                .accessibilityAddTraits(.isHeader)
            let lines = relationship.isEmpty ? [BLERelationshipText.Line(title: BLERelationshipText.noSuggestion)] : relationship
            ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                // The peripheral side always shows its tier; the LAN side only when several lines compete.
                lineView(line, showBadge: peripheral != nil || lines.count > 1)
            }
            ForEach(peripheralLinks) { link in
                NavigationLink(destination: BLEPeripheralDetailView(peripheralID: link.id)) {
                    HStack {
                        Image(systemName: BluetoothSymbol.name).foregroundColor(AppColors.info).accessibilityHidden(true)
                        Text(link.name).font(.subheadline.weight(.medium))
                        Spacer()
                        Image(systemName: "chevron.right").font(.caption).foregroundColor(.secondary).accessibilityHidden(true)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Bluetooth details for \(link.name)")
                .accessibilityHint("Opens what this Bluetooth device advertises")
            }
        }
    }

    @ViewBuilder private func lineView(_ line: BLERelationshipText.Line, showBadge: Bool) -> some View {
        let content = VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                if onOpenDevice != nil, line.deviceID != nil {
                    Image(systemName: "link.badge.plus").foregroundColor(AppColors.info).accessibilityHidden(true)
                }
                Text(line.title).font(.subheadline.weight(.medium)).multilineTextAlignment(.leading)
                Spacer(minLength: 0)
                if showBadge, let tier = line.tier { AppBadge(text: BLERelationshipText.badge(tier), color: AppColors.info) }
            }
            if let caption = line.caption { Text(caption).font(.caption).foregroundColor(.secondary) }
        }
        .contentShape(Rectangle())

        if let onOpenDevice, let deviceID = line.deviceID {
            Button { onOpenDevice(deviceID) } label: { content }
                .buttonStyle(.plain)
                .accessibilityElement(children: .combine)
                .accessibilityHint("Opens the network device")
        } else if let onOpenPeripheral, let peripheralID = line.peripheralID {
            Button { onOpenPeripheral(peripheralID) } label: { content }
                .buttonStyle(.plain)
                .accessibilityElement(children: .combine)
                .accessibilityHint("Opens the Bluetooth device")
        } else {
            content.accessibilityElement(children: .combine)
        }
    }

    // MARK: Facts

    @ViewBuilder private func facts(_ p: BLEPeripheral) -> some View {
        DetailRow(label: "Advertised name", value: p.parsed.displayName ?? "None")
        DetailRow(label: "Advertised company", value: Self.companyText(p.parsed))
        if !p.parsed.serviceUUIDs.isEmpty {
            DetailRow(label: "Services", value: p.parsed.serviceUUIDs.map { uuid in
                p.parsed.serviceNames[uuid].map { "\($0) (\(uuid))" } ?? uuid
            }.joined(separator: "\n"), selectable: true)
        }
        DetailRow(label: "Connectable", value: p.fields.isConnectable.map { $0 ? "Yes" : "No" } ?? "Unknown")
        if let tx = p.fields.txPower { DetailRow(label: "TX power", value: "\(tx) dBm") }
        DetailRow(label: "RSSI", value: "\(p.rssi) dBm")
        RSSISparkline(samples: p.rssiHistory.samples)
        if let data = p.fields.manufacturerData, !data.isEmpty {
            DetailRow(label: "Manufacturer data", value: Self.hex(data), selectable: true)
        }
        ForEach(p.fields.serviceData.keys.sorted(), id: \.self) { key in
            if let data = p.fields.serviceData[key] {
                DetailRow(label: "Service data \(BLEServiceNameTable.shortForm(key))", value: Self.hex(data), selectable: true)
            }
        }
        DetailRow(label: "First seen", value: p.firstSeen.formatted(date: .omitted, time: .standard))
        DetailRow(label: "Last seen", value: p.lastSeen.formatted(date: .omitted, time: .standard))
    }

    // MARK: Inferred

    @ViewBuilder private func inferred(_ p: BLEPeripheral) -> some View {
        Text("Inferred").font(.subheadline.weight(.semibold)).accessibilityAddTraits(.isHeader)
        inferredRow("Type guess: \(p.typeLabel)", detail: p.parsed.kindReason)
        if !p.parsed.continuity.isEmpty {
            let labels = p.parsed.continuity.map { $0.type?.label ?? String(format: "Type 0x%02X", $0.rawType) }
            inferredRow("Apple Continuity: \(labels.joined(separator: ", "))", detail: nil)
        }
        if let hint = p.parsed.continuityModelHint { inferredRow("Model hint: \(hint)", detail: nil) }
        if let model = p.parsed.fastPair?.modelID { inferredRow(String(format: "Fast Pair model ID: 0x%06X", model), detail: nil) }
        if let m = p.parsed.matter {
            inferredRow(String(format: "Matter vendor 0x%04X, product 0x%04X, discriminator %d", m.vendorID, m.productID, m.discriminator), detail: nil)
        }
        inferredRow("Distance: \(p.distance.label)", detail: nil)
    }

    private func inferredRow(_ title: String, detail: String?) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.subheadline)
            if let detail { Text(detail).font(.caption).foregroundColor(.secondary) }
            Text(Self.inferredCaption).font(.caption2).foregroundColor(.secondary)
        }
        .accessibilityElement(children: .combine)
    }

    // MARK: Device information

    @ViewBuilder private func deviceInformation(_ p: BLEPeripheral) -> some View {
        if let info = p.deviceInfo {
            Text("Device information (read on request)").font(.subheadline.weight(.semibold)).accessibilityAddTraits(.isHeader)
            if info.isEmpty {
                Text("The device returned no Device Information or Battery values.").font(.caption).foregroundColor(.secondary)
            }
            if let v = info.manufacturer { DetailRow(label: "Manufacturer", value: v, selectable: true) }
            if let v = info.model { DetailRow(label: "Model", value: v, selectable: true) }
            if let v = info.firmware { DetailRow(label: "Firmware", value: v, selectable: true) }
            if let v = info.batteryPercent { DetailRow(label: "Battery", value: "\(v)%") }
        } else if p.parsed.kind == .tracker {
            Text("Read device info is not offered for trackers.").font(.caption).foregroundColor(.secondary)
        } else if p.fields.isConnectable != false, let onReadInfo {
            Button(action: onReadInfo) {
                if p.readState == .reading {
                    HStack(spacing: 6) { ProgressView(); Text("Reading device info") }
                } else {
                    Text("Read device info")
                }
            }
            .buttonStyle(.bordered)
            .disabled(p.readState == .reading)
            .accessibilityHint("Asks before connecting once to read Device Information and Battery")
            if case .failed(let error) = p.readState {
                Text(Self.failureText(error)).font(.caption).foregroundColor(.secondary)
            }
        }
    }

    // MARK: Formatting

    static func companyText(_ parsed: BLEParsedAdvertisement) -> String {
        guard let id = parsed.companyID else { return "None" }
        let hexID = String(format: "0x%04X", id)
        return parsed.companyName.map { "\($0) (\(hexID))" } ?? "Unknown (\(hexID))"
    }

    static func hex(_ data: Data) -> String { HexFormatting.hex(data) }

    /// A cancelled read also arrives as `.timedOut`, so that text does not claim a timeout.
    static func failureText(_ error: BLEReadError) -> String {
        switch error {
        case .notFound: return "The device could not be found."
        case .connectFailed: return "Could not connect to the device."
        case .timedOut: return "The read did not finish. It ran out of time or was interrupted."
        case .noServices: return "The device does not offer Device Information or Battery."
        case .poweredOff: return "Bluetooth is off or unavailable."
        case .busy: return "Another read is running."
        }
    }
}
