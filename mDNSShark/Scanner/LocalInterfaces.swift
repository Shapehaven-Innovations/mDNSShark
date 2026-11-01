// mDNSShark/Scanner/LocalInterfaces.swift
import Foundation
import Darwin

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
        var addresses: [String] { ipv4 + ipv6 }
    }

    /// This device's own addresses as the scan merge needs them: `primary` ranks the row's display address, `all` is what a
    /// resolved row is matched against, since the phone answers mDNS from every interface, not only Wi-Fi.
    struct OwnAddresses: Equatable {
        /// The primary (Wi-Fi infrastructure) interface's addresses, raw with scope.
        var primary: [String]
        /// Every up, non-loopback interface's addresses, IPv4 and IPv6, raw with scope.
        var all: [String]

        init(primary: [String], all: [String]) {
            self.primary = primary
            self.all = all
        }

        /// One list standing for both, for tests and single-interface hosts.
        init(_ addresses: [String]) {
            self.init(primary: addresses, all: addresses)
        }

        static let none = OwnAddresses([])
    }

    static let wifiInfrastructureType: UInt32 = 3

    /// The live interfaces read once into an `OwnAddresses`.
    static func ownAddresses(from interfaces: [Interface] = interfaces()) -> OwnAddresses {
        OwnAddresses(primary: primaryInterface(from: interfaces)?.addresses ?? [], all: interfaces.flatMap(\.addresses))
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
            if family == AF_INET { byName[name]?.ipv4.append(text) } else { byName[name]?.ipv6.append(text) }
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

    private static func numericHost(_ addr: UnsafeMutablePointer<sockaddr>) -> String? {
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(addr, socklen_t(addr.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else {
            return nil
        }
        return String(cString: host)
    }
}
