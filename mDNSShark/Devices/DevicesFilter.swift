import Foundation

enum DevicesFilter: String, CaseIterable, Identifiable {
    case lan = "LAN", bluetooth = "Bluetooth"
    var id: String { rawValue }
}
