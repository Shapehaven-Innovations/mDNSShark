import Foundation
import DeviceFingerprint

/// The rows the Devices screen draws for one filter. Pure, so the section rules are tested without a view.
struct DevicesListPlan: Equatable {
    enum Row: Equatable, Identifiable {
        case lan(DiscoveredDevice)
        case peripheral(BLEPeripheral)
        case saved(BLESavedDevice)

        /// Prefixed so a LAN, live and saved id can never collide inside one `ForEach`.
        var id: String {
            switch self {
            case .lan(let d): return "lan-\(d.id.uuidString)"
            case .peripheral(let p): return "ble-\(p.id.uuidString)"
            case .saved(let s): return "saved-\(s.id.uuidString)"
            }
        }
    }

    /// An empty title draws no header.
    struct Section: Equatable, Identifiable {
        var title: String
        var rows: [Row]
        var id: String { title }
    }

    static let savedTitle = "Saved"

    var sections: [Section]
    var isEmpty: Bool { sections.allSatisfy { $0.rows.isEmpty } }

    static func make(filter: DevicesFilter, devices: [DiscoveredDevice], peripherals: [BLEPeripheral],
                     saved: [BLESavedDevice], now: Date) -> DevicesListPlan {
        let live = peripherals.filter { $0.lifecycle(now: now) != .expired }
        // A saved entry whose live row is still listed is drawn once, as that live row.
        let savedOnly = saved.filter { entry in !live.contains { $0.savedID == entry.id } }
        let lanRows = devices.map(Row.lan)

        switch filter {
        case .all:
            let rows = lanRows + live.map(Row.peripheral) + savedOnly.map(Row.saved)
            return DevicesListPlan(sections: rows.isEmpty ? [] : [Section(title: "", rows: rows)])
        case .lan:
            return DevicesListPlan(sections: lanRows.isEmpty ? [] : [Section(title: "", rows: lanRows)])
        case .bluetooth:
            return DevicesListPlan(sections: [
                Section(title: "", rows: live.filter { $0.savedID == nil }.map(Row.peripheral)),
                Section(title: savedTitle, rows: live.filter { $0.savedID != nil }.map(Row.peripheral) + savedOnly.map(Row.saved)),
            ])
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
