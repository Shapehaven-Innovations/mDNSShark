// mDNSSharkTests/ScannerAddressTests.swift
import Testing
import Network
import Foundation
import Darwin
@testable import mDNSShark

@Suite("Addresses are read with their IPv6 scope and the device's own interfaces are picked by type")
struct ScannerAddressTests {

    private func sockaddrData(v4 ip: String) -> Data {
        var sin = sockaddr_in()
        sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        sin.sin_family = sa_family_t(AF_INET)
        _ = ip.withCString { inet_pton(AF_INET, $0, &sin.sin_addr) }
        return withUnsafeBytes(of: &sin) { Data($0) }
    }

    private func sockaddrData(v6 ip: String, scope: UInt32 = 0) -> Data {
        var sin6 = sockaddr_in6()
        sin6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        sin6.sin6_family = sa_family_t(AF_INET6)
        sin6.sin6_scope_id = scope
        _ = ip.withCString { inet_pton(AF_INET6, $0, &sin6.sin6_addr) }
        return withUnsafeBytes(of: &sin6) { Data($0) }
    }

    // MARK: - ipAddress(fromSockaddr:)

    @Test("an IPv4 sockaddr reads as the plain dotted address")
    func ipv4ReadsPlain() {
        #expect(NetworkScanner.ipAddress(fromSockaddr: sockaddrData(v4: "192.0.2.1")) == "192.0.2.1")
    }

    @Test("a link-local IPv6 sockaddr keeps its scope as %interface, literally as getnameinfo prints it")
    func linkLocalIPv6KeepsScope() {
        let loopbackIndex = if_nametoindex("lo0")
        #expect(loopbackIndex != 0)
        #expect(NetworkScanner.ipAddress(fromSockaddr: sockaddrData(v6: "fe80::1", scope: loopbackIndex)) == "fe80::1%lo0")
    }

    @Test("a routable IPv6 sockaddr reads without a scope")
    func routableIPv6HasNoScope() {
        #expect(NetworkScanner.ipAddress(fromSockaddr: sockaddrData(v6: "2001:db8::1")) == "2001:db8::1")
    }

    @Test("data too short for a sockaddr reads as nil")
    func shortDataIsNil() {
        #expect(NetworkScanner.ipAddress(fromSockaddr: Data([0, 0, 0])) == nil)
    }

    // MARK: - Ranking with a scope suffix

    @Test("preferredAddress still ranks fe80 last and IP literals are still recognised when a %scope is present")
    func scopedAddressesRankAndParse() {
        #expect(NetworkScanner.preferredAddress(from: ["fe80::1%en0", "2001:db8::1"]) == "2001:db8::1")
        #expect(NetworkScanner.preferredAddress(from: ["fe80::1%en0", "169.254.1.1"]) == "169.254.1.1")
        #expect(NetworkScanner.preferredAddress(from: ["fe80::2%en0", "fe80::1%en0"]) == "fe80::1%en0")
        #expect(NetworkScanner.isIPAddressLiteral("fe80::1%en0"))
        #expect(NetworkScanViewModel.orderedAddresses(["fe80::1%en0", "203.0.113.5", "2001:db8::5", "169.254.9.9"])
                == ["203.0.113.5", "169.254.9.9", "2001:db8::5", "fe80::1%en0"])
    }

    @Test("a host seen on a scoped fe80 address and a LAN IPv4 is one device keyed by the IPv4")
    @MainActor
    func scopedAddressMergesIntoHost() {
        let vm = NetworkScanViewModel(ownAddresses: { [] }, probe: { _, _ in })
        let v6 = NetworkScanner.Device(serviceName: "Mac", serviceDomain: "local.", serviceType: "_airplay._tcp")
        v6.resolvedIPAddress = "fe80::1%en0"; v6.hostName = "Mac.local."; v6.resolveSettled = true
        let v4 = NetworkScanner.Device(serviceName: "Mac", serviceDomain: "local.", serviceType: "_ssh._tcp")
        v4.resolvedIPAddress = "203.0.113.5"; v4.hostName = "Mac.local."; v4.resolveSettled = true

        let devices = vm.merge(raw: [v6, v4])

        #expect(devices.map(\.ipAddress) == ["203.0.113.5"])
        #expect(devices[0].addresses == ["203.0.113.5", "fe80::1%en0"])
        #expect(devices[0].hostname == "Mac.local.")
    }

    @Test("a host known only by a scoped fe80 address keeps that address raw")
    @MainActor
    func scopedOnlyHostKeepsRawAddress() {
        let vm = NetworkScanViewModel(ownAddresses: { [] }, probe: { _, _ in })
        let row = NetworkScanner.Device(serviceName: "Mac", serviceDomain: "local.", serviceType: "_airplay._tcp")
        row.resolvedIPAddress = "fe80::1%en0"; row.hostName = "Mac.local."; row.resolveSettled = true

        let first = vm.merge(raw: [row])
        let again = vm.merge(raw: [row])

        #expect(first.map(\.ipAddress) == ["fe80::1%en0"])
        #expect(first.map(\.id) == again.map(\.id))
    }

    // MARK: - LocalInterfaces

    private func iface(_ name: String, type: UInt32?, v4: [String] = [], v6: [String] = []) -> LocalInterfaces.Interface {
        LocalInterfaces.Interface(name: name, functionalType: type, ipv4: v4, ipv6: v6)
    }

    @Test("an address is on the local network when it falls in an interface subnet or is self-assigned, and off it otherwise")
    func onLocalSubnet() {
        let lan = LocalInterfaces.IPv4Subnet(network: LocalInterfaces.ipv4Value("10.10.30.0")!, prefixLength: 24)
        let wide = LocalInterfaces.IPv4Subnet(network: LocalInterfaces.ipv4Value("10.10.30.0")!, prefixLength: 23)
        #expect(LocalInterfaces.isOnLocalSubnet(addresses: ["10.10.30.80"], subnets: [lan]) == true)
        #expect(LocalInterfaces.isOnLocalSubnet(addresses: ["10.10.10.87"], subnets: [lan]) == false)
        #expect(LocalInterfaces.isOnLocalSubnet(addresses: ["10.10.31.5"], subnets: [lan]) == false)
        #expect(LocalInterfaces.isOnLocalSubnet(addresses: ["10.10.31.5"], subnets: [wide]) == true)
        // A self-assigned peer is on this network only when this host has a 169.254 interface as well.
        let linkLocal = LocalInterfaces.IPv4Subnet(network: LocalInterfaces.ipv4Value("169.254.0.0")!, prefixLength: 16)
        #expect(LocalInterfaces.isOnLocalSubnet(addresses: ["169.254.4.4"], subnets: [lan]) == false)
        #expect(LocalInterfaces.isOnLocalSubnet(addresses: ["169.254.4.4"], subnets: [lan, linkLocal]) == true)
        #expect(LocalInterfaces.IPv4Subnet(network: 0, prefixLength: 0).contains(0xC0A8_0101))
        #expect(LocalInterfaces.IPv4Subnet(network: 0x0A0A_1E05, prefixLength: 32).contains(0x0A0A_1E05))
        #expect(!LocalInterfaces.IPv4Subnet(network: 0x0A0A_1E05, prefixLength: 32).contains(0x0A0A_1E06))
        #expect(LocalInterfaces.ipv4Value("256.1.1.1") == nil && LocalInterfaces.ipv4Value("1.2.3") == nil
                && LocalInterfaces.ipv4Value("1.2.3.4%en0") == nil)
        // One on-link address is enough, an IPv6-only device cannot be decided, and no known subnet means no verdict.
        #expect(LocalInterfaces.isOnLocalSubnet(addresses: ["10.10.10.87", "10.10.30.9"], subnets: [lan]) == true)
        #expect(LocalInterfaces.isOnLocalSubnet(addresses: ["fe80::1"], subnets: [lan]) == nil)
        #expect(LocalInterfaces.isOnLocalSubnet(addresses: ["10.10.10.87"], subnets: []) == nil)
    }

    @Test("a locally administered MAC is detected from its first octet, and clearing the bit gives the base address")
    func locallyAdministeredMAC() {
        #expect(MACAddressFacts.isLocallyAdministered("1a:e8:29:ac:a0:6b"))
        #expect(!MACAddressFacts.isLocallyAdministered("18:e8:29:ac:a0:6b"))
        #expect(MACAddressFacts.clearingLocalBit("1a:e8:29:ac:a0:6b") == "18:e8:29:ac:a0:6b")
        #expect(MACAddressFacts.clearingLocalBit("18:e8:29:ac:a0:6b") == nil)
        #expect(!MACAddressFacts.isLocallyAdministered("zz") && !MACAddressFacts.isLocallyAdministered(""))

        var router = DiscoveredDevice(hostname: "192.168.203.1", ipAddress: "192.168.203.1", macAddress: "1a:e8:29:ac:a0:6b")
        #expect(router.hasLocallyAdministeredMAC)
        let withVendor = router.macNote { $0 == "18:e8:29:ac:a0:6b" ? "Ubiquiti Inc" : nil }
        #expect(withVendor?.contains("18:e8:29:ac:a0:6b") == true && withVendor?.contains("Ubiquiti Inc") == true && withVendor?.contains("inferred") == true)
        #expect(router.macNote { _ in nil }?.contains("cannot be read") == true)
        router.macAddress = "18:e8:29:ac:a0:6b"
        #expect(router.macNote { _ in "x" } == nil && !router.hasLocallyAdministeredMAC)
    }

    @Test("gateway endpoints are read as IPv4 literals, ignoring IPv6 and any zone")
    func gatewayEndpoints() {
        let v4 = NWEndpoint.hostPort(host: .ipv4(IPv4Address("192.168.203.1")!), port: 0)
        let v6 = NWEndpoint.hostPort(host: .ipv6(IPv6Address("fe80::1%en0")!), port: 0)
        #expect(GatewayMonitor.ipv4Addresses(of: [v4, v6]) == ["192.168.203.1"])
        #expect(GatewayMonitor.ipv4Addresses(of: [v6]).isEmpty)
        #expect(GatewayMonitor.ipv4Addresses(of: []).isEmpty)
    }

    @Test("a netmask is a prefix length only when it is a contiguous run of ones")
    func netmaskPrefixLength() {
        #expect(LocalInterfaces.prefixLength(maskBits: 0) == 0)
        #expect(LocalInterfaces.prefixLength(maskBits: 0xFF00_0000) == 8)
        #expect(LocalInterfaces.prefixLength(maskBits: 0xFFFF_FF00) == 24)
        #expect(LocalInterfaces.prefixLength(maskBits: 0xFFFF_FFFE) == 31)
        #expect(LocalInterfaces.prefixLength(maskBits: 0xFFFF_FFFF) == 32)
        #expect(LocalInterfaces.prefixLength(maskBits: 0xFF00_FF00) == nil)
        #expect(LocalInterfaces.prefixLength(maskBits: 0x0000_FFFF) == nil)
    }

    @Test("the Wi-Fi infrastructure interface is chosen by type, preferring the one that carries an IPv4 address")
    func primaryInterfacePicksWiFiByType() {
        let interfaces = [
            iface("en5", type: 6, v4: ["169.254.3.3"]),
            iface("llw0", type: 3, v6: ["fe80::2%llw0"]),
            iface("en1", type: 3, v4: ["192.168.8.123"], v6: ["fe80::1%en1", "2001:db8::123"]),
            iface("awdl0", type: 4, v6: ["fe80::3%awdl0"])
        ]
        let primary = LocalInterfaces.primaryInterface(from: interfaces)
        #expect(primary?.name == "en1")
        #expect(primary?.addresses == ["192.168.8.123", "fe80::1%en1", "2001:db8::123"])
    }

    @Test("when no interface reports the Wi-Fi type, an en* interface with an address is the fallback")
    func primaryInterfaceFallsBackToEthernetLike() {
        let interfaces = [iface("utun0", type: nil, v6: ["fd00::1"]), iface("en0", type: nil, v4: ["10.0.0.2"])]
        #expect(LocalInterfaces.primaryInterface(from: interfaces)?.name == "en0")
        #expect(LocalInterfaces.primaryInterface(from: [iface("utun0", type: nil, v6: ["fd00::1"])]) == nil)
        #expect(LocalInterfaces.primaryInterface(from: []) == nil)
    }

    @Test("the primary IPv4 is picked by preference, so a 169.254 address listed first never beats the LAN address")
    func primaryIPv4PrefersLANOverLinkLocal() {
        let interfaces = [iface("en0", type: 3, v4: ["169.254.3.3", "192.168.8.123"], v6: ["fe80::1%en0"])]
        #expect(LocalInterfaces.primaryIPv4Address(from: interfaces) == "192.168.8.123")
        #expect(LocalInterfaces.primaryIPv4Address(from: [iface("en0", type: 3, v4: ["169.254.3.3"])]) == "169.254.3.3")
        #expect(LocalInterfaces.primaryIPv4Address(from: [iface("en0", type: 3, v6: ["fe80::1%en0"])]) == nil)
    }

    @Test("ownAddresses pairs the Wi-Fi interface's addresses with every interface's, in interface order and raw with scope")
    func ownAddressesCoverEveryInterface() {
        let interfaces = [
            iface("en0", type: 3, v4: ["192.168.8.123"], v6: ["fe80::b4:adc4:1fbe:7245%en0"]),
            iface("llw0", type: 3, v6: ["fe80::1%llw0"]),
            iface("en2", type: 6, v4: ["169.254.249.30"], v6: ["fe80::14eb:e0d:cd05:4494%en2"]),
            iface("anpi0", type: 6, v6: ["fe80::4cf1:16ff:fe45:e1b8%anpi0"])
        ]
        let own = LocalInterfaces.ownAddresses(from: interfaces)
        #expect(own.primary == ["192.168.8.123", "fe80::b4:adc4:1fbe:7245%en0"])
        #expect(own.all == ["192.168.8.123", "fe80::b4:adc4:1fbe:7245%en0", "fe80::1%llw0", "169.254.249.30",
                            "fe80::14eb:e0d:cd05:4494%en2", "fe80::4cf1:16ff:fe45:e1b8%anpi0"])
        #expect(LocalInterfaces.ownAddresses(from: []) == .none)
        #expect(LocalInterfaces.OwnAddresses(["10.0.0.2"]) == LocalInterfaces.OwnAddresses(primary: ["10.0.0.2"], all: ["10.0.0.2"]))
    }

    @Test("the address match key drops the zone and case but nothing else, and is never used for display")
    func addressMatchKeyIgnoresZoneAndCase() {
        #expect(LocalInterfaces.addressMatchKey("fe80::4cf1:16ff:fe45:e1b8%anpi0") == "fe80::4cf1:16ff:fe45:e1b8")
        #expect(LocalInterfaces.addressMatchKey("FE80::AAAA%en0") == LocalInterfaces.addressMatchKey("fe80::aaaa%anpi0"))
        #expect(LocalInterfaces.addressMatchKey("192.168.8.123") == "192.168.8.123")
        #expect(LocalInterfaces.addressMatchKey("2001:db8::1") == "2001:db8::1")
        #expect(LocalInterfaces.addressMatchKey("fe80::1") != LocalInterfaces.addressMatchKey("fe80::2"))
    }

    @Test("the live interface list never contains loopback and reports only numeric addresses, fe80 ones with a scope")
    func liveInterfacesAreNumericAndScoped() {
        let interfaces = LocalInterfaces.interfaces()
        #expect(!interfaces.contains { $0.name == "lo0" })
        for interface in interfaces {
            for address in interface.addresses { #expect(NetworkScanner.isIPAddressLiteral(address)) }
            for v6 in interface.ipv6 where v6.lowercased().hasPrefix("fe80") { #expect(v6.contains("%")) }
            for v4 in interface.ipv4 { #expect(!v4.contains(":")) }
        }
        let primary = LocalInterfaces.primaryAddresses()
        #expect(primary == (LocalInterfaces.primaryInterface()?.addresses ?? []))
        let own = LocalInterfaces.ownAddresses()
        #expect(own.primary == primary)
        #expect(own.all == interfaces.flatMap(\.addresses))
        #expect(Set(own.primary).isSubset(of: Set(own.all)))
    }
}
