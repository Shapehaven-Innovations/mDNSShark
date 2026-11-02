import Foundation

public enum AppGroup {
    public static let identifier = "group.beta.mDNSShark"
}

public enum WidgetKind {
    public static let devices = "devices"
    public static let security = "security"
    public static let newDevices = "newdevices"
    public static let scan = "scan"
    public static let mix = "mix"
    public static let topology = "topology"
    public static let capture = "capture"

    /// Every kind except capture, in display order.
    public static let scanKinds: [String] = [devices, security, newDevices, scan, mix, topology]
}

public enum WidgetLink {
    /// Parsed by the app's DeepLinkRouter, which owns the URL scheme.
    public static let devicesTab = URL(string: "mdnsshark://tab/devices")!
}

public struct StatusCounts: Codable, Equatable, Sendable {
    public var total: Int
    public var secure: Int
    public var warning: Int
    public var critical: Int
    public var notProbed: Int
    public var pending: Int

    public init(total: Int, secure: Int, warning: Int, critical: Int, notProbed: Int, pending: Int) {
        self.total = total
        self.secure = secure
        self.warning = warning
        self.critical = critical
        self.notProbed = notProbed
        self.pending = pending
    }

    public static let zero = StatusCounts(total: 0, secure: 0, warning: 0, critical: 0, notProbed: 0, pending: 0)
}

public struct ScanSample: Codable, Equatable, Sendable {
    public var at: Date
    public var counts: StatusCounts

    public init(at: Date, counts: StatusCounts) {
        self.at = at
        self.counts = counts
    }
}

public struct DeviceBrief: Codable, Equatable, Sendable {
    public var key: String
    public var name: String
    public var ip: String
    public var typeLabel: String
    public var symbol: String
    public var status: String
    public var offNetwork: Bool
    public var isGateway: Bool
    public var firstSeen: Date

    public init(key: String, name: String, ip: String, typeLabel: String, symbol: String, status: String,
                offNetwork: Bool, isGateway: Bool, firstSeen: Date) {
        self.key = key
        self.name = name
        self.ip = ip
        self.typeLabel = typeLabel
        self.symbol = symbol
        self.status = status
        self.offNetwork = offNetwork
        self.isGateway = isGateway
        self.firstSeen = firstSeen
    }

    /// The lowercased MAC when present, else "ip:" plus the literal address.
    public static func key(mac: String?, ip: String) -> String {
        if let mac, !mac.isEmpty { return mac.lowercased() }
        return "ip:" + ip
    }
}

public struct WidgetSnapshot: Codable, Equatable, Sendable {
    public static let schemaVersion = 1

    public var version: Int
    public var scannedAt: Date
    public var subnet: String?
    public var counts: StatusCounts
    public var typeCounts: [String: Int]
    public var history: [ScanSample]
    public var newDevices: [DeviceBrief]
    public var topology: [DeviceBrief]
    public var topologyOverflow: Int
    public var ownDeviceKey: String?

    public init(version: Int, scannedAt: Date, subnet: String?, counts: StatusCounts, typeCounts: [String: Int],
                history: [ScanSample], newDevices: [DeviceBrief], topology: [DeviceBrief],
                topologyOverflow: Int, ownDeviceKey: String?) {
        self.version = version
        self.scannedAt = scannedAt
        self.subnet = subnet
        self.counts = counts
        self.typeCounts = typeCounts
        self.history = history
        self.newDevices = newDevices
        self.topology = topology
        self.topologyOverflow = topologyOverflow
        self.ownDeviceKey = ownDeviceKey
    }
}
