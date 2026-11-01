// mDNSSharkTests/SubnetHeaderSweepTests.swift
import Testing
import Foundation
@testable import mDNSShark

@Suite("Not probed text, real CIDR in the header, and a sweep that stays inside the subnet")
struct SubnetHeaderSweepTests {
    typealias Subnet = LocalInterfaces.IPv4Subnet

    private func subnet(_ ip: String, _ prefix: Int) -> Subnet {
        let mask = prefix == 0 ? 0 : ~UInt32(0) << UInt32(32 - prefix)
        return Subnet(network: LocalInterfaces.ipv4Value(ip)! & mask, prefixLength: prefix)
    }

    @Test("open-ports text is Not probed for an off-subnet row and a payment skip, None for a probed row")
    func noOpenPortsText() {
        var off = DiscoveredDevice(hostname: "cam", ipAddress: "10.10.10.87")
        off.isOnLocalSubnet = false
        var skipped = DiscoveredDevice(hostname: "pos", ipAddress: "10.10.30.40")
        skipped.paymentVendorSkip = PaymentVendorSkip(vendor: "PAX", inferred: false, sentARPTrigger: false)
        var probed = DiscoveredDevice(hostname: "tv", ipAddress: "10.10.30.41")
        probed.isOnLocalSubnet = true
        #expect(off.noOpenPortsText == "Not probed")
        #expect(skipped.noOpenPortsText == "Not probed")
        #expect(probed.noOpenPortsText == "None")
    }

    @Test("cidr prints the dotted network and the prefix length")
    func cidrFormatting() {
        #expect(subnet("10.10.30.44", 24).cidr == "10.10.30.0/24")
        #expect(subnet("10.10.31.44", 23).cidr == "10.10.30.0/23")
        #expect(subnet("172.16.40.9", 16).cidr == "172.16.0.0/16")
        #expect(subnet("192.168.1.77", 28).cidr == "192.168.1.64/28")
    }

    @Test("the header shows the primary subnet's CIDR, else the old /24 text")
    @MainActor func headerCIDR() {
        let withSubnet = NetworkScanViewModel(ownAddresses: {
            LocalInterfaces.OwnAddresses(primary: ["10.10.30.44"], all: ["10.10.30.44"], primarySubnet: Subnet(network: 0x0A0A1E00, prefixLength: 23))
        })
        #expect(withSubnet.networkCIDR == "10.10.30.0/23")
        let none = NetworkScanViewModel(ownAddresses: { LocalInterfaces.OwnAddresses.none })
        #expect(none.networkCIDR == "\(LocalDeviceScanner().getLocalIPPrefix().map { "\($0)0/24" } ?? "Unknown")")
    }

    @Test("a /24 or a missing subnet sweeps .1 to .254 of the phone's /24")
    func sweep24AndNil() {
        let expected = (1...254).map { "10.10.30.\($0)" }
        #expect(LocalDeviceScanner.sweepTargets(ownIPv4: "10.10.30.44", subnet: subnet("10.10.30.44", 24)) == expected)
        #expect(LocalDeviceScanner.sweepTargets(ownIPv4: "10.10.30.44", subnet: nil) == expected)
    }

    @Test("a /23 stays capped to the phone's /24")
    func sweep23() {
        let targets = LocalDeviceScanner.sweepTargets(ownIPv4: "10.10.31.44", subnet: subnet("10.10.31.44", 23))
        #expect(targets == (1...254).map { "10.10.31.\($0)" })
    }

    @Test("a /26 and a /28 sweep only host addresses inside the subnet")
    func sweepNarrow() {
        let s26 = LocalDeviceScanner.sweepTargets(ownIPv4: "192.168.1.70", subnet: subnet("192.168.1.70", 26))
        #expect(s26 == (65...126).map { "192.168.1.\($0)" })
        let s28 = LocalDeviceScanner.sweepTargets(ownIPv4: "192.168.1.70", subnet: subnet("192.168.1.70", 28))
        #expect(s28 == (65...78).map { "192.168.1.\($0)" })
    }

    @Test("a /31 sweeps only its peer and a /32 sweeps nothing")
    func sweepPointToPoint() {
        #expect(LocalDeviceScanner.sweepTargets(ownIPv4: "192.168.1.70", subnet: subnet("192.168.1.70", 31)) == ["192.168.1.71"])
        #expect(LocalDeviceScanner.sweepTargets(ownIPv4: "192.168.1.71", subnet: subnet("192.168.1.70", 31)) == ["192.168.1.70"])
        #expect(LocalDeviceScanner.sweepTargets(ownIPv4: "192.168.1.70", subnet: subnet("192.168.1.70", 32)).isEmpty)
    }

    @Test("the .1 gateway guess is dropped when it lies outside a /26")
    func gatewayGuessOutsideSlash26() {
        let s26 = subnet("192.168.1.70", 26)
        #expect(LocalDeviceScanner.defaultGateway(prefix: "192.168.1.", subnet: s26, gateways: []) == nil)
        #expect(LocalDeviceScanner.defaultGateway(prefix: "192.168.1.", subnet: s26, gateways: ["192.168.1.65"]) == "192.168.1.65")
        #expect(LocalDeviceScanner.defaultGateway(prefix: "192.168.1.", subnet: s26, gateways: ["192.168.1.1"]) == nil)
        #expect(LocalDeviceScanner.defaultGateway(prefix: "192.168.1.", subnet: nil, gateways: []) == "192.168.1.1")
    }

    @Test("a /23 gateway on the other half of the pair is matched by containment")
    func gatewayMatchedBySlash23() {
        let s23 = subnet("10.10.31.44", 23)
        #expect(LocalDeviceScanner.defaultGateway(prefix: "10.10.31.", subnet: s23, gateways: ["10.10.30.1"]) == "10.10.30.1")
        #expect(LocalDeviceScanner.defaultGateway(prefix: "10.10.31.", subnet: s23, gateways: []) == "10.10.31.1")
    }
}
