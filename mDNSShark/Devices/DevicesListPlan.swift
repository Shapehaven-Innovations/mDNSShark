import Foundation
import DeviceFingerprint

/// The rows the Devices screen draws for one filter. Pure, so the section rules are tested without a view.
struct DevicesListPlan: Equatable {
    enum Row: Equatable, Identifiable {
        case lan(DiscoveredDevice, bluetoothSuggested: Bool)
        case peripheral(BLEPeripheral)
        case saved(BLESavedDevice)

        /// Prefixed so a LAN, live and saved id can never collide inside one `ForEach`.
        var id: String {
            switch self {
            case .lan(let d, _): return "lan-\(d.id.uuidString)"
            case .peripheral(let p): return "ble-\(p.id.uuidString)"
            case .saved(let s): return "saved-\(s.id.uuidString)"
            }
        }
    }

    struct Section: Equatable, Identifiable {
        var title: String
        var rows: [Row]
        var id: String { title }
    }

    static let suggestedTitle = "Suggested on your network", notOnNetworkTitle = "Not on network", savedTitle = "Saved"

    var sections: [Section]
    var isEmpty: Bool { sections.allSatisfy { $0.rows.isEmpty } }

    static func make(filter: DevicesFilter, devices: [DiscoveredDevice], peripherals: [BLEPeripheral],
                     saved: [BLESavedDevice], matches: BLEMatchTable, now: Date) -> DevicesListPlan {
        let live = peripherals.filter { $0.lifecycle(now: now) != .expired }
        let suggestedPeripherals = matches.suggestedPeripheralIDs
        let suggestedDevices = matches.suggestedDeviceIDs
        // A saved entry whose live row is still listed is drawn once, as that live row.
        let savedOnly = saved.filter { entry in !live.contains { $0.savedID == entry.id } }
        let lanRows = devices.map { Row.lan($0, bluetoothSuggested: suggestedDevices.contains($0.id)) }
        let unsuggested = live.filter { !suggestedPeripherals.contains($0.id) }

        switch filter {
        case .all:
            let rows = lanRows + unsuggested.map(Row.peripheral) + savedOnly.map(Row.saved)
            return DevicesListPlan(sections: rows.isEmpty ? [] : [Section(title: "", rows: rows)])
        case .lan:
            return DevicesListPlan(sections: lanRows.isEmpty ? [] : [Section(title: "", rows: lanRows)])
        case .bluetooth:
            var sections: [Section] = []
            let suggested = live.filter { suggestedPeripherals.contains($0.id) }
            if !suggested.isEmpty { sections.append(Section(title: suggestedTitle, rows: suggested.map(Row.peripheral))) }
            sections.append(Section(title: notOnNetworkTitle,
                                    rows: unsuggested.filter { $0.savedID == nil }.map(Row.peripheral)))
            // A saved peripheral that is suggested stays under Suggested, so every peripheral is listed once.
            sections.append(Section(title: savedTitle,
                                    rows: unsuggested.filter { $0.savedID != nil }.map(Row.peripheral) + savedOnly.map(Row.saved)))
            return DevicesListPlan(sections: sections)
        }
    }
}

/// What the Bluetooth part of Devices can show, from authorization first and then the radio's power.
enum BluetoothAccessState: Equatable {
    case ready, undetermined, denied, restricted, poweredOff, unsupported

    static func from(authorization: BLEAuthorization, power: BLEPowerState) -> BluetoothAccessState {
        switch authorization {
        case .denied: return .denied
        case .restricted: return .restricted
        default: break
        }
        if power == .unsupported { return .unsupported }
        if power == .poweredOff { return .poweredOff }
        if authorization == .undetermined { return .undetermined }
        return .ready
    }
}
