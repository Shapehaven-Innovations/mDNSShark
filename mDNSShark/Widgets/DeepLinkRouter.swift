// mDNSShark/Widgets/DeepLinkRouter.swift
import Foundation

struct DeviceTarget: Equatable {
    var mac: String?
    var ip: String?
}

enum DeepLink: Equatable {
    case tab(AppTab)
    case device(DeviceTarget)
}

@MainActor
final class DeepLinkRouter: ObservableObject {
    @Published var deviceLinkID: UUID?
    private(set) var pendingTarget: DeviceTarget?

    nonisolated static func parse(_ url: URL) -> DeepLink? {
        guard url.scheme?.lowercased() == "mdnsshark" else { return nil }
        switch url.host?.lowercased() {
        case "tab":
            let name = url.pathComponents.dropFirst().first?.lowercased() ?? ""
            return AppTab.allCases.first { $0.rawValue.lowercased() == name }.map(DeepLink.tab)
        case "device":
            let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
            func value(_ key: String) -> String? {
                items.first { $0.name == key }?.value.flatMap { $0.isEmpty ? nil : $0 }
            }
            let target = DeviceTarget(mac: value("mac"), ip: value("ip"))
            return target.mac == nil && target.ip == nil ? .tab(.devices) : .device(target)
        default:
            return nil
        }
    }

    /// Matches by MAC across all rows first, then by IP; never by the row's UUID, which changes every scan.
    nonisolated static func match(_ target: DeviceTarget, in devices: [DiscoveredDevice]) -> DiscoveredDevice? {
        if let mac = target.mac?.lowercased(),
           let hit = devices.first(where: { $0.macAddress?.lowercased() == mac }) { return hit }
        if let ip = target.ip {
            return devices.first { $0.ipAddress == ip || $0.addresses.contains(ip) }
        }
        return nil
    }

    func open(_ url: URL, devices: [DiscoveredDevice], isScanning: Bool) -> AppTab? {
        guard let link = Self.parse(url) else { return nil }
        switch link {
        case .tab(let tab):
            return tab
        case .device(let target):
            pendingTarget = nil
            if let hit = Self.match(target, in: devices) {
                deviceLinkID = hit.id
            } else if isScanning || devices.isEmpty {
                pendingTarget = target
            }
            return .devices
        }
    }

    func devicesChanged(_ devices: [DiscoveredDevice]) {
        guard let target = pendingTarget, let hit = Self.match(target, in: devices) else { return }
        pendingTarget = nil
        deviceLinkID = hit.id
    }

    func scanFinished() {
        pendingTarget = nil
    }
}
