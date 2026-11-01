// mDNSShark/Scanner/LocalInterfaces.swift
import Foundation
import Darwin
import Network

/// This device's own network interfaces, read with getifaddrs and classified with the SIOCGIFFUNCTIONALTYPE ioctl,
/// so the Wi-Fi link is chosen by type rather than by the iOS-only "en0" name. Addresses are returned exactly as
/// getnameinfo prints them, so a link-local IPv6 keeps its "%scope" suffix.
enum LocalInterfaces {
    struct Interface: Equatable {
        let name: String
        /// SIOCGIFFUNCTIONALTYPE value (IFRTYPE_FUNCTIONAL_WIFI_INFRA is 3), nil when the ioctl failed.
        let functionalType: UInt32?
        var ipv4: [String]
        var ipv6: [String]
        /// The subnet each IPv4 address sits on, read from the interface netmask; empty when none was reported.
        var ipv4Subnets: [IPv4Subnet] = []
        var addresses: [String] { ipv4 + ipv6 }
    }

    /// An IPv4 network as an address and prefix length, for asking whether another address is on the same link.
    struct IPv4Subnet: Equatable {
        let network: UInt32
        let prefixLength: Int

        func contains(_ address: UInt32) -> Bool {
            prefixLength == 0 ? true : (address ^ network) >> UInt32(32 - prefixLength) == 0
        }
    }

    /// Parses a dotted IPv4 literal into its 32-bit value, nil for anything else (IPv6, hostnames, zone-suffixed text).
    static func ipv4Value(_ text: String) -> UInt32? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var value: UInt32 = 0
        for part in parts {
            guard let octet = UInt8(part) else { return nil }
            value = value << 8 | UInt32(octet)
        }
        return value
    }

    /// Whether a device with these addresses is on the network this phone or Mac is connected to: true when an IPv4 address lies in one of
    /// `subnets` (a self-assigned 169.254 peer counts only when this host has a 169.254 interface too), false when it has IPv4 addresses and
    /// none do, and nil when nothing can be decided (no subnets known, no IPv4 address since IPv6 scopes are not compared, or only
    /// self-assigned addresses with no 169.254 interface here, since a failed DHCP lease on this Wi-Fi looks the same).
    static func isOnLocalSubnet(addresses: [String], subnets: [IPv4Subnet]) -> Bool? {
        guard !subnets.isEmpty else { return nil }
        let values = addresses.compactMap(ipv4Value)
        guard !values.isEmpty else { return nil }
        if values.contains(where: { value in subnets.contains { $0.contains(value) } }) { return true }
        if values.allSatisfy({ $0 >> 16 == 0xA9FE }) { return nil }
        return false
    }

    /// This device's own addresses as the scan merge needs them: `primary` ranks the row's display address, `all` is what a
    /// resolved row is matched against, since the phone answers mDNS from every interface, not only Wi-Fi.
    struct OwnAddresses: Equatable {
        /// The primary (Wi-Fi infrastructure) interface's addresses, raw with scope.
        var primary: [String]
        /// Every up, non-loopback interface's addresses, IPv4 and IPv6, raw with scope.
        var all: [String]
        /// The IPv4 subnets this device is on, from every up interface's netmask; empty in tests and when none was reported.
        var ipv4Subnets: [IPv4Subnet] = []
        /// The default gateways' IPv4 addresses as the system reports them; empty when unknown, and then the ".1" guess is the fallback.
        var gatewaysIPv4: [String] = []

        init(primary: [String], all: [String], ipv4Subnets: [IPv4Subnet] = [], gatewaysIPv4: [String] = []) {
            self.primary = primary
            self.all = all
            self.ipv4Subnets = ipv4Subnets
            self.gatewaysIPv4 = gatewaysIPv4
        }

        /// One list standing for both, for tests and single-interface hosts.
        init(_ addresses: [String]) {
            self.init(primary: addresses, all: addresses)
        }

        static let none = OwnAddresses([])
    }

    static let wifiInfrastructureType: UInt32 = 3

    /// The live interfaces with the system's default gateways added, for the scan merge.
    static func liveOwnAddresses() -> OwnAddresses {
        var own = ownAddresses()
        own.gatewaysIPv4 = GatewayMonitor.shared.ipv4
        return own
    }

    /// The live interfaces read once into an `OwnAddresses`.
    static func ownAddresses(from interfaces: [Interface] = interfaces()) -> OwnAddresses {
        OwnAddresses(primary: primaryInterface(from: interfaces)?.addresses ?? [], all: interfaces.flatMap(\.addresses),
                     ipv4Subnets: interfaces.flatMap(\.ipv4Subnets))
    }

    /// Internal match key for an address: the "%zone" suffix dropped and lowercased, since getifaddrs and a resolve can name the
    /// scope differently for the same link-local address. Never displayed.
    static func addressMatchKey(_ address: String) -> String {
        (address.split(separator: "%", maxSplits: 1).first.map(String.init) ?? address).lowercased()
    }

    /// Interfaces that are up and running, not loopback and not point-to-point, with their numeric addresses.
    static func interfaces() -> [Interface] {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return [] }
        defer { freeifaddrs(ifaddr) }
        // One socket serves every interface's functional-type ioctl, instead of one socket per interface.
        let sock = socket(AF_INET, SOCK_DGRAM, 0)
        defer { if sock >= 0 { close(sock) } }
        var byName: [String: Interface] = [:]
        var order: [String] = []
        for ptr in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let entry = ptr.pointee
            let flags = Int32(entry.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_RUNNING != 0, flags & IFF_LOOPBACK == 0, flags & IFF_POINTOPOINT == 0,
                  let addr = entry.ifa_addr else { continue }
            let family = Int32(addr.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }
            let name = String(cString: entry.ifa_name)
            if byName[name] == nil {
                let type = sock >= 0 ? functionalType(of: name, socket: sock) : nil
                byName[name] = Interface(name: name, functionalType: type, ipv4: [], ipv6: [])
                order.append(name)
            }
            guard let text = numericHost(addr) else { continue }
            if family == AF_INET {
                byName[name]?.ipv4.append(text)
                if let value = ipv4Value(text), let mask = entry.ifa_netmask, let prefix = prefixLength(of: mask) {
                    byName[name]?.ipv4Subnets.append(IPv4Subnet(network: prefixLength(prefix, applyTo: value), prefixLength: prefix))
                }
            } else { byName[name]?.ipv6.append(text) }
        }
        return order.compactMap { byName[$0] }
    }

    /// The Wi-Fi infrastructure interface, preferring one that carries an IPv4 address; when no interface reports that type
    /// (ioctl failure, or a wired Mac), the first en* interface with an address.
    static func primaryInterface(from interfaces: [Interface] = interfaces()) -> Interface? {
        func rank(_ i: Interface) -> (Int, Int, String) { (i.ipv4.isEmpty ? 1 : 0, i.ipv6.isEmpty ? 1 : 0, i.name) }
        let wifi = interfaces.filter { $0.functionalType == wifiInfrastructureType && !$0.addresses.isEmpty }
        if let best = wifi.min(by: { rank($0) < rank($1) }) { return best }
        let ethernetLike = interfaces.filter { $0.name.hasPrefix("en") && !$0.addresses.isEmpty }
        return ethernetLike.min(by: { rank($0) < rank($1) })
    }

    /// Every address of the primary interface, IPv4 first, then IPv6 with scope.
    static func primaryAddresses() -> [String] { primaryInterface()?.addresses ?? [] }

    /// The primary interface's IPv4 by preference (LAN before 169.254), not by getifaddrs order, so a self-assigned address never wins.
    static func primaryIPv4Address(from interfaces: [Interface] = interfaces()) -> String? {
        primaryInterface(from: interfaces).flatMap { NetworkScanner.preferredAddress(from: $0.ipv4) }
    }

    /// SIOCGIFFUNCTIONALTYPE is not importable into Swift, so its request number _IOWR('i', 173, struct ifreq) is built here.
    private static let functionalTypeRequest: UInt =
        UInt(0xC000_0000) | UInt((MemoryLayout<ifreq>.size & 0x1fff) << 16) | UInt(UInt8(ascii: "i")) << 8 | 173

    private static func functionalType(of name: String, socket fd: Int32) -> UInt32? {
        var req = ifreq()
        withUnsafeMutablePointer(to: &req.ifr_name) { field in
            field.withMemoryRebound(to: CChar.self, capacity: Int(IFNAMSIZ)) { _ = strlcpy($0, name, Int(IFNAMSIZ)) }
        }
        guard ioctl(fd, functionalTypeRequest, &req) == 0 else { return nil }
        return req.ifr_ifru.ifru_functional_type
    }

    /// The prefix length of an IPv4 netmask sockaddr. getifaddrs may trim trailing zero bytes (sa_len 5 or 7), so only the bytes sa_len
    /// covers are read, through a raw pointer, and the rest count as zero.
    private static func prefixLength(of mask: UnsafeMutablePointer<sockaddr>) -> Int? {
        let base = UnsafeRawPointer(mask)
        let length = min(Int(base.load(as: UInt8.self)), 8)
        guard length > 4 else { return nil }
        var bits: UInt32 = 0
        for index in 4..<length { bits = bits << 8 | UInt32(base.load(fromByteOffset: index, as: UInt8.self)) }
        bits <<= UInt32(8 * (8 - length))
        return prefixLength(maskBits: bits)
    }

    /// The prefix length of a netmask value, nil unless it is a contiguous run of ones from the top.
    static func prefixLength(maskBits bits: UInt32) -> Int? {
        let ones = bits.nonzeroBitCount
        return bits == (ones == 0 ? 0 : ~UInt32(0) << UInt32(32 - ones)) ? ones : nil
    }

    private static func prefixLength(_ prefix: Int, applyTo value: UInt32) -> UInt32 {
        prefix == 0 ? 0 : value & (~UInt32(0) << UInt32(32 - prefix))
    }

    private static func numericHost(_ addr: UnsafeMutablePointer<sockaddr>) -> String? {
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(addr, socklen_t(addr.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else {
            return nil
        }
        return String(cString: host)
    }
}

/// The default gateways the system reports for the current network path (NWPath.gateways, public API, no entitlement). It starts at first
/// use and keeps the latest answer, so reading `ipv4` is cheap and never waits.
final class GatewayMonitor {
    static let shared = GatewayMonitor()

    private let monitor = NWPathMonitor()
    private let lock = NSLock()
    private var current: [String] = []

    private init() {
        monitor.pathUpdateHandler = { [weak self] path in
            let addresses = Self.ipv4Addresses(of: path.gateways)
            self?.lock.lock(); self?.current = addresses; self?.lock.unlock()
        }
        monitor.start(queue: DispatchQueue(label: "GatewayMonitor"))
    }

    var ipv4: [String] {
        lock.lock(); defer { lock.unlock() }
        return current
    }

    /// The IPv4 literals among the gateway endpoints, as received; IPv6 gateways are ignored here.
    static func ipv4Addresses(of endpoints: [NWEndpoint]) -> [String] {
        endpoints.compactMap { endpoint -> String? in
            guard case let .hostPort(host, _) = endpoint, case let .ipv4(address) = host else { return nil }
            return String(describing: address).split(separator: "%").first.map(String.init)
        }
    }
}

