// mDNSShark/Devices/BluetoothCardView.swift
import SwiftUI
import DeviceFingerprint

/// The Bluetooth card on the peripheral detail screen: advertised facts, inferences and the on-request device information.
struct BluetoothCardView: View {
    let peripheral: BLEPeripheral
    var onReadInfo: (() -> Void)? = nil

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
                facts(peripheral)
                Divider()
                inferred(peripheral)
                Divider()
                deviceInformation(peripheral)
            }
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
        DetailRow(label: "Fingerprint", value: Self.fingerprintText(p.fingerprint), selectable: true)
        DetailRow(label: "Identifiers", value: Self.identifiersText(p), selectable: true)
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
        if let cdp = p.parsed.cdp {
            let kind = cdp.deviceTypeLabel ?? "device type \(cdp.deviceType)"
            inferredRow("Microsoft beacon: \(kind)", detail: "Its address and hash change constantly, so it cannot be tied to one device across rotations")
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
                Text("The device returned no Device Information, Battery or Heart Rate values.").font(.caption).foregroundColor(.secondary)
            }
            if let v = info.manufacturer { DetailRow(label: "Manufacturer", value: v, selectable: true) }
            if let v = info.model { DetailRow(label: "Model", value: v, selectable: true) }
            if let v = info.firmware { DetailRow(label: "Firmware", value: v, selectable: true) }
            if let v = info.batteryPercent { DetailRow(label: "Battery", value: "\(v)%") }
            if let v = info.heartRateBPM { DetailRow(label: "Heart rate", value: "\(v) bpm") }
        } else if !p.parsed.kind.offersDeviceInfoRead {
            Text("Read device info is not offered for trackers or Find My beacons.").font(.caption).foregroundColor(.secondary)
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
            .accessibilityHint("Asks before connecting once to read Device Information, Battery and one heart rate measurement")
            if case .failed(let error) = p.readState {
                Text(Self.failureText(error)).font(.caption).foregroundColor(.secondary)
            }
        }
    }

    // MARK: Formatting

    /// What this row merges on, or why it cannot merge when a rotated address arrives.
    static func fingerprintText(_ fingerprint: BLEFingerprint?) -> String {
        guard let key = fingerprint?.key else { return "None (no name, Matter or Fast Pair data, so a new address becomes a new row)" }
        switch key {
        case let .matter(vendor, product, discriminator):
            return String(format: "Matter 0x%04X / 0x%04X / %d", vendor, product, discriminator)
        case let .fastPair(model):
            return String(format: "Fast Pair model 0x%06X", model)
        case let .name(name, company):
            return "Name \(name), company \(company.map { String(format: "0x%04X", $0) } ?? "none")"
        }
    }

    /// One line per CoreBluetooth identifier the row holds, newest first, so a split or merge can be traced.
    static func identifiersText(_ p: BLEPeripheral) -> String {
        p.identifierTraces.sorted { $0.value.joinedAt > $1.value.joinedAt }.map { id, trace in
            "\(id.uuidString.prefix(8)) joined \(trace.joinedAt.formatted(date: .omitted, time: .standard)), \(trace.lastRSSI) dBm"
        }.joined(separator: "\n")
    }

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
        case .notOffered: return "Read device info is not offered for this kind of device."
        }
    }
}
