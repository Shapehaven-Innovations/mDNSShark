// mDNSSharkTests/ProbeGateTests.swift
import Testing
import Foundation
@testable import mDNSShark

@MainActor
@Suite("Probe gate: a host off this phone's networks gets no automatic probes and counts as settled")
struct ProbeGateTests {
    private final class Log { var ips: [String] = [] }

    private let phone = "10.10.30.5"

    private func viewModel(log: Log) -> NetworkScanViewModel {
        let subnet = LocalInterfaces.IPv4Subnet(network: LocalInterfaces.ipv4Value("10.10.30.0")!, prefixLength: 24)
        let own = LocalInterfaces.OwnAddresses(primary: [phone], all: [phone], ipv4Subnets: [subnet])
        return NetworkScanViewModel(ownAddresses: { own }, probe: { ip, _ in log.ips.append(ip) })
    }

    private func bonjourRow(type: String = "_http._tcp", name: String, ip: String, host: String, location: URL? = nil) -> NetworkScanner.Device {
        let row = NetworkScanner.Device(serviceName: name, serviceDomain: "local.", serviceType: type)
        row.resolvedIPAddress = ip
        row.hostName = host
        row.port = 80
        row.resolveSettled = true
        row.locationURL = location
        return row
    }

    @Test("an outside host is never probed, is settled, and is flagged off-subnet")
    func outsideHostNotProbed() {
        let log = Log()
        let vm = viewModel(log: log)
        let row = bonjourRow(name: "Cam", ip: "10.10.10.87", host: "cam.local.")

        let devices = vm.merge(raw: [row])
        _ = vm.merge(raw: [row])

        #expect(log.ips.isEmpty)
        #expect(devices.map(\.probesSettled) == [true])
        #expect(devices.map(\.isOnLocalSubnet) == [false])
    }

    @Test("an inside host is probed exactly once across merges")
    func insideHostProbedOnce() {
        let log = Log()
        let vm = viewModel(log: log)
        let row = bonjourRow(name: "Printer", ip: "10.10.30.40", host: "printer.local.")

        let devices = vm.merge(raw: [row])
        _ = vm.merge(raw: [row])

        #expect(log.ips == ["10.10.30.40"])
        #expect(devices.map(\.probesSettled) == [false])
        #expect(devices.map(\.isOnLocalSubnet) == [true])
    }

    @Test("the phone's own row is probed as before")
    func ownRowStillProbed() {
        let log = Log()
        let vm = viewModel(log: log)

        let devices = vm.merge(raw: [bonjourRow(name: "Phone", ip: phone, host: "phone.local.")])

        #expect(log.ips == [phone])
        #expect(devices.count == 1)
        #expect(devices.first?.isOnLocalSubnet == true)
    }

    @Test("an outside host skips the description fetch and Google Wifi probe, an inside googlecast host with a LOCATION runs both")
    func existingBranchStaysGated() {
        let log = Log()
        var fetches: [String] = []
        var wifi: [String] = []
        let subnet = LocalInterfaces.IPv4Subnet(network: LocalInterfaces.ipv4Value("10.10.30.0")!, prefixLength: 24)
        let own = LocalInterfaces.OwnAddresses(primary: [phone], all: [phone], ipv4Subnets: [subnet])
        let vm = NetworkScanViewModel(ownAddresses: { own }, probe: { ip, _ in log.ips.append(ip) },
                                      descriptionFetch: { ip, _ in fetches.append(ip) }, googleWifi: { wifi.append($0) })
        let outURL = URL(string: "http://10.10.10.87:49152/desc.xml")
        let inURL = URL(string: "http://10.10.30.60:49152/desc.xml")
        let out1 = bonjourRow(type: "_googlecast._tcp", name: "Cast", ip: "10.10.10.87", host: "cast.local.")
        let out2 = bonjourRow(type: "_googlecast._tcp", name: "Cast2", ip: "10.10.10.87", host: "cast.local.", location: outURL)
        let in1 = bonjourRow(type: "_googlecast._tcp", name: "Hub", ip: "10.10.30.60", host: "hub.local.")
        let in2 = bonjourRow(type: "_googlecast._tcp", name: "Hub2", ip: "10.10.30.60", host: "hub.local.", location: inURL)

        let devices = vm.merge(raw: [out1, out2, in1, in2])

        #expect(devices.count == 2)
        #expect(log.ips == ["10.10.30.60"])
        #expect(fetches == ["10.10.30.60"])
        #expect(wifi == ["10.10.30.60"])
        #expect(devices.first { $0.isOnLocalSubnet == false }?.probesSettled == true)
    }

    @Test("an address first refused as off-subnet is still probed once a later merge adds an on-subnet address to its host")
    func laterOnSubnetAddressProbes() {
        let log = Log()
        let vm = viewModel(log: log)
        let a = bonjourRow(name: "A", ip: "10.10.10.87", host: "h.local.")
        let b = bonjourRow(name: "B", ip: "10.10.30.87", host: "h.local.")

        let first = vm.merge(raw: [a])
        #expect(log.ips.isEmpty)
        #expect(first.map(\.probesSettled) == [true])

        let devices = vm.merge(raw: [a, b])

        #expect(devices.count == 1)
        #expect(log.ips == ["10.10.30.87"])
        #expect(devices.map(\.probesSettled) == [false])
    }

    @Test("a host first seen IPv6-only and then given an on-subnet IPv4 is probed at the IPv4 and reads as probed")
    func ipv6ThenIPv4Probes() {
        let log = Log()
        let vm = viewModel(log: log)
        let v6 = bonjourRow(type: "_matter._tcp", name: "A", ip: "fd12::1", host: "h.local.")
        let v4 = bonjourRow(name: "B", ip: "10.10.30.87", host: "h.local.")

        let first = vm.merge(raw: [v6])
        #expect(first.map(\.probeRefused) == [true])

        let devices = vm.merge(raw: [v6, v4])

        #expect(devices.count == 1)
        #expect(log.ips == ["10.10.30.87"])
        #expect(devices.map(\.probesSettled) == [false])
        #expect(devices.map(\.probeRefused) == [false])
    }

    @Test("an off-subnet first IPv4 that sorts above a later on-subnet one is still un-skipped")
    func laterLowerOnSubnetAddressProbes() {
        let log = Log()
        let vm = viewModel(log: log)
        let a = bonjourRow(name: "A", ip: "10.10.50.5", host: "h.local.")
        let b = bonjourRow(name: "B", ip: "10.10.30.9", host: "h.local.")

        _ = vm.merge(raw: [a])
        #expect(log.ips.isEmpty)

        let devices = vm.merge(raw: [a, b])

        #expect(log.ips == ["10.10.30.9"])
        #expect(devices.map(\.probesSettled) == [false])
        #expect(devices.map(\.probeRefused) == [false])
    }

    @Test("an IPv6-only group (Thread, Matter) is never probed, is settled, and reads Not probed")
    func ipv6OnlyNotProbed() {
        let log = Log()
        let vm = viewModel(log: log)
        let row = bonjourRow(type: "_matter._tcp", name: "Sensor", ip: "fd12:3456:789a::1", host: "sensor.local.")

        let devices = vm.merge(raw: [row])
        _ = vm.merge(raw: [row])

        #expect(log.ips.isEmpty)
        #expect(devices.map(\.probesSettled) == [true])
    }

    @Test("a non-LAN address with no known subnet is refused, settled, and reads Not probed")
    func nonLANRefused() {
        let log = Log()
        let own = LocalInterfaces.OwnAddresses(primary: [phone], all: [phone])
        let vm = NetworkScanViewModel(ownAddresses: { own }, probe: { ip, _ in log.ips.append(ip) })

        let devices = vm.merge(raw: [bonjourRow(name: "Far", ip: "8.8.8.8", host: "far.local.")])

        #expect(log.ips.isEmpty)
        #expect(devices.map(\.probesSettled) == [true])
    }

    @Test("an IPv4 group is still probed and reads None until ports are found")
    func ipv4GroupProbed() {
        let log = Log()
        let vm = viewModel(log: log)

        let devices = vm.merge(raw: [bonjourRow(name: "Printer", ip: "10.10.30.41", host: "p.local.")])

        #expect(log.ips == ["10.10.30.41"])
    }

    @Test("a Hue row without a TXT vendor leaves the manufacturer nil so the OUI lookup can fill it")
    func hueLeavesManufacturerNil() {
        let vm = viewModel(log: Log())
        let devices = vm.merge(raw: [bonjourRow(type: "_hue._tcp", name: "Bridge", ip: "10.10.30.50", host: "hue.local.")])
        #expect(devices.first?.manufacturer == nil)
    }
}
