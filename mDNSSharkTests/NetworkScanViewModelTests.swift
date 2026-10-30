// mDNSSharkTests/NetworkScanViewModelTests.swift
import Testing
import Foundation
@testable import mDNSShark

@MainActor
@Suite("NetworkScanViewModel advertised versus open ports")
struct NetworkScanViewModelTests {

    // TEST-NET-3 addresses: the enrichment coordinator refuses non-LAN-local IPs, so merge() fires no probes.
    private func bonjourRow(type: String, name: String, ip: String, port: Int) -> NetworkScanner.Device {
        let row = NetworkScanner.Device(serviceName: name, serviceDomain: "local.", serviceType: type)
        row.resolvedIPAddress = ip
        row.port = port
        return row
    }

    // Issue #13: an Amcrest camera on another VLAN advertises _http._tcp on port 80 but accepts no connection.
    @Test("a Bonjour-advertised port stays on the service and never enters openPorts")
    func advertisedPortIsNotOpen() {
        let vm = NetworkScanViewModel()
        let camera = bonjourRow(type: "_http._tcp", name: "AMC060E7AF0A5BCE81", ip: "203.0.113.87", port: 80)

        let devices = vm.merge(raw: [camera])

        #expect(devices.count == 1)
        #expect(devices[0].openPorts.isEmpty)
        #expect(devices[0].bonjourServices.map(\.port) == [80])
    }

    @Test("a second advertised service for the same host adds no open port either")
    func secondAdvertisementIsNotOpen() {
        let vm = NetworkScanViewModel()
        let http = bonjourRow(type: "_http._tcp", name: "nas", ip: "203.0.113.10", port: 80)
        let ssh = bonjourRow(type: "_ssh._tcp", name: "nas", ip: "203.0.113.10", port: 22)

        let devices = vm.merge(raw: [http, ssh])

        #expect(devices.count == 1)
        #expect(devices[0].openPorts.isEmpty)
        #expect(Set(devices[0].bonjourServices.map(\.port)) == [22, 80])
    }

    @Test("an SSDP LOCATION port is not an open port until the description fetch succeeds")
    func ssdpLocationPortIsNotOpen() {
        let vm = NetworkScanViewModel()
        let row = NetworkScanner.Device(serviceName: "uuid:tv", serviceDomain: "ssdp", serviceType: "ssdp")
        row.resolvedIPAddress = "203.0.113.20"
        row.port = 49152
        row.locationURL = URL(string: "http://203.0.113.20:49152/desc.xml")

        let devices = vm.merge(raw: [row])

        #expect(devices.count == 1)
        #expect(devices[0].openPorts.isEmpty)
        #expect(devices[0].bonjourServices.isEmpty)
    }

    @Test("a successful SSDP description fetch confirms exactly the LOCATION port")
    func ssdpDescriptionConfirmsLocationPort() {
        #expect(DeviceEnrichmentCoordinator.confirmedPorts(descriptionURL: URL(string: "http://192.168.1.1:49152/desc.xml")) == [49152])
        #expect(DeviceEnrichmentCoordinator.confirmedPorts(descriptionURL: URL(string: "http://192.168.1.1/desc.xml")) == [80])
        #expect(DeviceEnrichmentCoordinator.confirmedPorts(descriptionURL: nil).isEmpty)
    }
}
