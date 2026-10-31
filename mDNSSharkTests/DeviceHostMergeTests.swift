// mDNSSharkTests/DeviceHostMergeTests.swift
import Testing
import Foundation
@testable import mDNSShark

@MainActor
@Suite("Bonjour services attach to their host instead of becoming devices")
struct DeviceHostMergeTests {

    // TEST-NET-3 and documentation-range addresses: the enrichment coordinator refuses them, so merge() fires no probes.
    private func bonjourRow(type: String, name: String, ip: String?, host: String?, port: Int = 80) -> NetworkScanner.Device {
        let row = NetworkScanner.Device(serviceName: name, serviceDomain: "local.", serviceType: type)
        row.resolvedIPAddress = ip
        row.hostName = host
        row.port = port
        return row
    }

    @Test("a service that resolved to the host's link-local IPv4 merges into the host's LAN row")
    func linkLocalServiceMergesIntoHost() {
        let vm = NetworkScanViewModel()
        let lan = bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)
        let burst = bonjourRow(type: "_http._tcp", name: "burst150", ip: "169.254.46.247", host: "Mac.local.", port: 8150)

        let devices = vm.merge(raw: [lan, burst])

        #expect(devices.count == 1)
        #expect(devices[0].ipAddress == "203.0.113.10")
        #expect(Set(devices[0].bonjourServices.map(\.serviceType)) == ["_ssh._tcp", "_http._tcp"])
    }

    @Test("the LAN address wins even when the link-local row arrives first")
    func linkLocalRowFirstStillKeysByLANAddress() {
        let vm = NetworkScanViewModel()
        let burst = bonjourRow(type: "_http._tcp", name: "burst150", ip: "169.254.46.247", host: "Mac.local.", port: 8150)
        let lan = bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)

        let devices = vm.merge(raw: [burst, lan])

        #expect(devices.count == 1)
        #expect(devices[0].ipAddress == "203.0.113.10")
    }

    @Test("an IPv6-only row still collapses onto the host's IPv4 row")
    func ipv6RowCollapsesOntoIPv4() {
        let vm = NetworkScanViewModel()
        let airplay = bonjourRow(type: "_airplay._tcp", name: "Apple TV", ip: "2001:db8::7", host: "Apple-TV.local.", port: 7000)
        let raop = bonjourRow(type: "_raop._tcp", name: "AABB@Apple TV", ip: "203.0.113.7", host: "Apple-TV.local.", port: 7000)

        let devices = vm.merge(raw: [airplay, raop])

        #expect(devices.count == 1)
        #expect(devices[0].ipAddress == "203.0.113.7")
        #expect(devices[0].bonjourServices.count == 2)
    }

    @Test("a host with only IPv6 addresses keeps one IPv6 row, as the phone itself does")
    func ipv6OnlyHostKeepsOneRow() {
        let vm = NetworkScanViewModel()
        let rdlink = bonjourRow(type: "_rdlink._tcp", name: "iPhone", ip: "2001:db8::1", host: "iPhone.local.", port: 49152)
        let companion = bonjourRow(type: "_companion-link._tcp", name: "iPhone", ip: "2001:db8::1", host: "iPhone.local.", port: 49153)

        let devices = vm.merge(raw: [rdlink, companion])

        #expect(devices.count == 1)
        #expect(devices[0].ipAddress == "2001:db8::1")
        #expect(devices[0].bonjourServices.count == 2)
    }

    @Test("a service that never resolved does not become a device row")
    func unresolvedServiceCreatesNoRow() {
        let vm = NetworkScanViewModel()
        let pending = bonjourRow(type: "_http._tcp", name: "burst37", ip: nil, host: nil, port: 8037)
        let resolved = bonjourRow(type: "_http._tcp", name: "nas", ip: "203.0.113.20", host: "nas.local.")

        let devices = vm.merge(raw: [pending, resolved])

        #expect(devices.map(\.ipAddress) == ["203.0.113.20"])
    }

    @Test("rows without a Bonjour host name still key by their own address")
    func rowsWithoutHostNameKeyByIP() {
        let vm = NetworkScanViewModel()
        let sweep = NetworkScanner.Device(serviceName: "203.0.113.30", serviceDomain: "local", serviceType: "tcp")
        sweep.resolvedIPAddress = "203.0.113.30"
        let ssdp = NetworkScanner.Device(serviceName: "uuid:tv", serviceDomain: "ssdp", serviceType: "ssdp")
        ssdp.resolvedIPAddress = "203.0.113.31"

        let devices = vm.merge(raw: [sweep, ssdp])

        #expect(devices.map(\.ipAddress) == ["203.0.113.30", "203.0.113.31"])
    }

    @Test("a fallback-resolved row carrying only the host name folds into the host's IP row")
    func fallbackHostNameRowFoldsIntoHost() {
        let vm = NetworkScanViewModel()
        // DNSServiceResolver's fallback stores the host target in resolvedIPAddress, so both fields hold the name.
        let fallback = bonjourRow(type: "_http._tcp", name: "burst12", ip: "Mac.local.", host: "Mac.local.", port: 8012)
        let lan = bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)

        let devices = vm.merge(raw: [fallback, lan])

        #expect(devices.map(\.ipAddress) == ["203.0.113.10"])
        #expect(devices[0].bonjourServices.count == 2)
    }

    @Test("the scanner prefers a LAN IPv4 over link-local IPv4 over IPv6 over a bare host name")
    func preferredAddressOrder() {
        #expect(NetworkScanner.preferredAddress(from: ["169.254.46.247", "192.168.1.10"]) == "192.168.1.10")
        #expect(NetworkScanner.preferredAddress(from: ["fe80::1", "169.254.46.247"]) == "169.254.46.247")
        #expect(NetworkScanner.preferredAddress(from: ["fe80::1", "2001:db8::1"]) == "fe80::1")
        #expect(NetworkScanner.preferredAddress(from: ["192.168.1.10", "192.168.1.11"]) == "192.168.1.10")
        #expect(NetworkScanner.preferredAddress(from: ["Mac.local.", "fe80::1"]) == "fe80::1")
        #expect(NetworkScanner.preferredAddress(from: ["Mac.local."]) == "Mac.local.")
        #expect(NetworkScanner.preferredAddress(from: []) == nil)
    }
}
