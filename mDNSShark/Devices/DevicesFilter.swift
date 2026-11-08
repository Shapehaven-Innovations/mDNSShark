import Foundation

enum DevicesFilter: String, CaseIterable, Identifiable {
    case all = "All", lan = "LAN", bluetooth = "Bluetooth"
    var id: String { rawValue }
}
