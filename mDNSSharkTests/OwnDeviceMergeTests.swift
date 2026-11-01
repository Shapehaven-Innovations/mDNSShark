// mDNSSharkTests/OwnDeviceMergeTests.swift
import Testing
import Foundation
@testable import mDNSShark

@MainActor
@Suite("Device addresses and the phone's own row")
struct OwnDeviceMergeTests {

    // Own addresses are injected and probes are swallowed, so no traffic leaves the test.
    private func viewModel(own: [String]) -> NetworkScanViewModel {
        NetworkScanViewModel(ownAddresses: { own }, probe: { _, _ in })
    }

    private func viewModel(own: LocalInterfaces.OwnAddresses) -> NetworkScanViewModel {
        NetworkScanViewModel(ownAddresses: { own }, probe: { _, _ in })
    }

    // The field case: Wi-Fi en0 with the LAN IPv4, a wired en2 link to a Mac, and anpi0 with only a link-local IPv6.
    private let fieldWiFi = ["192.168.8.123", "fe80::b4:adc4:1fbe:7245%en0"]
    private var fieldPhone: LocalInterfaces.OwnAddresses {
        LocalInterfaces.OwnAddresses(primary: fieldWiFi,
                                     all: fieldWiFi + ["169.254.249.30", "fe80::14eb:e0d:cd05:4494%en2", "fe80::4cf1:16ff:fe45:e1b8%anpi0"])
    }

    private func bonjourRow(type: String, name: String, ip: String?, host: String?, port: Int = 80) -> NetworkScanner.Device {
        let row = NetworkScanner.Device(serviceName: name, serviceDomain: "local.", serviceType: type)
        row.resolvedIPAddress = ip
        row.hostName = host
        row.port = port
        row.resolveSettled = true
        return row
    }

    private func sweepRow(_ ip: String) -> NetworkScanner.Device {
        let row = NetworkScanner.Device(serviceName: ip, serviceDomain: "local", serviceType: "tcp")
        row.resolvedIPAddress = ip
        row.resolveSettled = true
        return row
    }

    private let phone = ["192.168.8.123", "fe80::aaaa%en0", "2001:db8::123"]

    // MARK: - addresses

    @Test("addresses lists every address of the host, IPv4 first then IPv6, raw and de-duplicated, in a stable order")
    func addressesListEveryAddressOfHost() {
        let rows = [
            bonjourRow(type: "_airplay._tcp", name: "Mac", ip: "fe80::1%en0", host: "Mac.local.", port: 7000),
            bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22),
            bonjourRow(type: "_http._tcp", name: "Mac", ip: "169.254.46.247", host: "Mac.local.", port: 80),
            bonjourRow(type: "_raop._tcp", name: "Mac", ip: "2001:db8::7", host: "Mac.local.", port: 7000),
            bonjourRow(type: "_smb._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 445)
        ]

        let forward = viewModel(own: []).merge(raw: rows)
        let reversed = viewModel(own: []).merge(raw: rows.reversed())

        #expect(forward.map(\.ipAddress) == ["203.0.113.10"])
        #expect(forward[0].addresses == ["203.0.113.10", "169.254.46.247", "2001:db8::7", "fe80::1%en0"])
        #expect(reversed[0].addresses == forward[0].addresses)
    }

    @Test("a device with one address lists just that address")
    func singleAddressDevice() {
        let devices = viewModel(own: []).merge(raw: [sweepRow("203.0.113.30")])
        #expect(devices[0].addresses == ["203.0.113.30"])
    }

    @Test("addresses take part in equality so a newly seen address redraws the row")
    func addressesTakePartInEquality() {
        var a = DiscoveredDevice(hostname: "a", ipAddress: "203.0.113.30", addresses: ["203.0.113.30"])
        let b = a
        a.addresses.append("fe80::1%en0")
        #expect(a != b)
    }

    // MARK: - This device

    @Test("the phone's own row is keyed by its Wi-Fi IPv4 even when Bonjour only resolved its fe80 address, and is never hidden")
    func ownRowShowsWiFiIPv4() {
        let rdlink = bonjourRow(type: "_rdlink._tcp", name: "iPhone", ip: "fe80::aaaa%en0", host: "iPhone.local.", port: 49152)

        let devices = viewModel(own: phone).merge(raw: [rdlink])

        #expect(devices.count == 1)
        #expect(devices[0].ipAddress == "192.168.8.123")
        #expect(devices[0].hostname == "iPhone.local.")
        #expect(devices[0].addresses == ["192.168.8.123", "2001:db8::123", "fe80::aaaa%en0"])
    }

    @Test("the phone's row is keyed by its LAN IPv4 even when its own 169.254 address is listed first")
    func ownRowPrefersLANIPv4OverLinkLocalFirst() {
        let rdlink = bonjourRow(type: "_rdlink._tcp", name: "iPhone", ip: "fe80::aaaa%en0", host: "iPhone.local.", port: 49152)

        let devices = viewModel(own: ["169.254.3.3", "192.168.8.123", "fe80::aaaa%en0"]).merge(raw: [rdlink])

        #expect(devices.map(\.ipAddress) == ["192.168.8.123"])
        #expect(devices[0].addresses == ["192.168.8.123", "169.254.3.3", "fe80::aaaa%en0"])
    }

    @Test("matching is a set intersection: one shared IPv6 out of several is enough")
    func ownRowMatchedBySetIntersection() {
        let companion = bonjourRow(type: "_companion-link._tcp", name: "iPhone", ip: "2001:db8::123", host: "iPhone.local.", port: 49153)

        let devices = viewModel(own: phone).merge(raw: [companion])

        #expect(devices.map(\.ipAddress) == ["192.168.8.123"])
    }

    @Test("a sweep hit on the phone's IPv4 and its Bonjour row on fe80 fold into one device")
    func ownIPv4SweepAndIPv6BonjourRowFold() {
        let rows = [sweepRow("192.168.8.123"),
                    bonjourRow(type: "_rdlink._tcp", name: "iPhone", ip: "fe80::aaaa%en0", host: "iPhone.local.", port: 49152)]

        let devices = viewModel(own: phone).merge(raw: rows)

        #expect(devices.count == 1)
        #expect(devices[0].ipAddress == "192.168.8.123")
        #expect(devices[0].hostname == "iPhone.local.")
        #expect(devices[0].bonjourServices.map(\.serviceType) == ["_rdlink._tcp"])
    }

    @Test("another host on a different fe80 address is left on its own address")
    func otherLinkLocalHostUntouched() {
        let other = bonjourRow(type: "_rdlink._tcp", name: "iPad", ip: "fe80::bbbb%en0", host: "iPad.local.", port: 49152)

        let devices = viewModel(own: phone).merge(raw: [other])

        #expect(devices.map(\.ipAddress) == ["fe80::bbbb%en0"])
        #expect(devices[0].addresses == ["fe80::bbbb%en0"])
    }

    @Test("on an IPv6-only network the phone's row takes its best own address rather than fe80")
    func ownRowWithoutIPv4PrefersRoutableIPv6() {
        let rdlink = bonjourRow(type: "_rdlink._tcp", name: "iPhone", ip: "fe80::aaaa%en0", host: "iPhone.local.", port: 49152)

        let devices = viewModel(own: ["fe80::aaaa%en0", "2001:db8::123"]).merge(raw: [rdlink])

        #expect(devices.map(\.ipAddress) == ["2001:db8::123"])
    }

    // MARK: - Own addresses from every interface

    @Test("a Bonjour row resolved to the phone's address on a non-Wi-Fi interface still folds onto its Wi-Fi IPv4, listing every own address")
    func ownRowFoldsOnAddressFromAnotherInterface() {
        let rdlink = bonjourRow(type: "_rdlink._tcp", name: "iPhone", ip: "fe80::4cf1:16ff:fe45:e1b8%anpi0", host: "iPhone.local.", port: 49152)

        let devices = viewModel(own: fieldPhone).merge(raw: [rdlink])

        #expect(devices.map(\.ipAddress) == ["192.168.8.123"])
        #expect(devices[0].hostname == "iPhone.local.")
        #expect(devices[0].addresses == ["192.168.8.123", "169.254.249.30", "fe80::14eb:e0d:cd05:4494%en2",
                                         "fe80::4cf1:16ff:fe45:e1b8%anpi0", "fe80::b4:adc4:1fbe:7245%en0"])
    }

    @Test("the phone is one row among the router and the Mac, and a sweep hit on its IPv4 folds into it")
    func ownRowIsSingleAmongOtherDevices() {
        let rows = [
            sweepRow("192.168.8.1"),
            bonjourRow(type: "_smb._tcp", name: "Mac", ip: "192.168.8.50", host: "Mac.local.", port: 445),
            bonjourRow(type: "_rdlink._tcp", name: "iPhone", ip: "fe80::4cf1:16ff:fe45:e1b8%anpi0", host: "iPhone.local.", port: 49152),
            sweepRow("192.168.8.123")
        ]

        let devices = viewModel(own: fieldPhone).merge(raw: rows)

        #expect(devices.map(\.ipAddress) == ["192.168.8.1", "192.168.8.123", "192.168.8.50"])
        #expect(devices[1].hostname == "iPhone.local.")
        #expect(devices[1].bonjourServices.map(\.serviceType) == ["_rdlink._tcp"])
    }

    @Test("a zone or case difference between the resolved address and getifaddrs does not break the match; the resolved spelling is kept once")
    func zoneDifferenceDoesNotBreakMatch() {
        let rdlink = bonjourRow(type: "_rdlink._tcp", name: "iPhone", ip: "FE80::AAAA%anpi0", host: "iPhone.local.", port: 49152)

        let devices = viewModel(own: ["192.168.8.123", "fe80::aaaa%en0"]).merge(raw: [rdlink])

        #expect(devices.map(\.ipAddress) == ["192.168.8.123"])
        #expect(devices[0].addresses == ["192.168.8.123", "FE80::AAAA%anpi0"])
    }

    @Test("another host on a link-local address of its own is untouched, even on the same interface as the phone's")
    func otherHostOnSameInterfaceUntouched() {
        let other = bonjourRow(type: "_rdlink._tcp", name: "iPad", ip: "fe80::bbbb%anpi0", host: "iPad.local.", port: 49152)

        let devices = viewModel(own: fieldPhone).merge(raw: [other])

        #expect(devices.map(\.ipAddress) == ["fe80::bbbb%anpi0"])
        #expect(devices[0].addresses == ["fe80::bbbb%anpi0"])
    }

    @Test("on an IPv6-only network a row matched on another interface's fe80 still shows the Wi-Fi routable IPv6")
    func ownRowIPv6OnlyMatchedOnOtherInterface() {
        let wifi = ["fe80::aaaa%en0", "2001:db8::123"]
        let own = LocalInterfaces.OwnAddresses(primary: wifi, all: wifi + ["fe80::cccc%anpi0"])
        let rdlink = bonjourRow(type: "_rdlink._tcp", name: "iPhone", ip: "fe80::cccc%anpi0", host: "iPhone.local.", port: 49152)

        let devices = viewModel(own: own).merge(raw: [rdlink])

        #expect(devices.map(\.ipAddress) == ["2001:db8::123"])
        #expect(devices[0].addresses == ["2001:db8::123", "fe80::aaaa%en0", "fe80::cccc%anpi0"])
    }

    @Test("the Wi-Fi IPv4 stays the row address even when a wired interface carries a LAN IPv4 that sorts first")
    func wiFiIPv4BeatsWiredLANIPv4() {
        let own = LocalInterfaces.OwnAddresses(primary: ["192.168.8.123"], all: ["192.168.8.123", "10.0.0.5"])
        let rdlink = bonjourRow(type: "_rdlink._tcp", name: "iPhone", ip: "10.0.0.5", host: "iPhone.local.", port: 49152)

        let devices = viewModel(own: own).merge(raw: [rdlink])

        #expect(devices.map(\.ipAddress) == ["192.168.8.123"])
        #expect(devices[0].addresses == ["10.0.0.5", "192.168.8.123"])
    }

    @Test("with no Wi-Fi interface, any own IPv4 is the row address")
    func noPrimaryInterfaceFallsBackToAnyOwnIPv4() {
        let own = LocalInterfaces.OwnAddresses(primary: [], all: ["fe80::cccc%en5", "169.254.249.30"])
        let rdlink = bonjourRow(type: "_rdlink._tcp", name: "iPhone", ip: "fe80::cccc%en5", host: "iPhone.local.", port: 49152)

        #expect(viewModel(own: own).merge(raw: [rdlink]).map(\.ipAddress) == ["169.254.249.30"])
    }

    @Test("the phone's row keeps its UUID across merges")
    func ownRowKeepsStableID() {
        let vm = viewModel(own: phone)
        let rdlink = bonjourRow(type: "_rdlink._tcp", name: "iPhone", ip: "fe80::aaaa%en0", host: "iPhone.local.", port: 49152)

        let first = vm.merge(raw: [rdlink])
        let second = vm.merge(raw: [rdlink, sweepRow("192.168.8.123")])

        #expect(first.map(\.id) == second.map(\.id))
    }
}
