// mDNSSharkTests/ProbesSettledTests.swift
import Testing
import Foundation
import DeviceFingerprint
@testable import mDNSShark

/// Records the addresses the view model asked to probe, standing in for the enrichment coordinator so no traffic is sent.
private final class ProbeLog {
    var ips: [String] = []
}

@MainActor
@Suite("probesSettled: a device's open ports are facts only once its probe set has answered")
struct ProbesSettledTests {

    // 10.0.0.x is LAN-local, so the coordinator would probe it; the log stands in for it. 203.0.113.x (TEST-NET-3) is refused.
    private func viewModel(log: ProbeLog = ProbeLog()) -> NetworkScanViewModel {
        NetworkScanViewModel(ownAddresses: { [] }, probe: { ip, _ in log.ips.append(ip) })
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

    @Test("a probed device stays pending until its address reports, even with an all-timeout empty result")
    func pendingUntilProbeAnswers() {
        let log = ProbeLog()
        let vm = viewModel(log: log)
        let sweep = sweepRow("10.0.0.5")

        let before = vm.merge(raw: [sweep])
        #expect(before.map(\.probesSettled) == [false])
        #expect(log.ips == ["10.0.0.5"])

        vm.ingestEnrichment(ip: "10.0.0.5", enrichments: [])
        let after = vm.merge(raw: [sweep])
        #expect(after.map(\.probesSettled) == [true])
        #expect(after[0].openPorts.isEmpty)
    }

    @Test("a device whose only address the coordinator refuses is settled at once, with nothing probed")
    func refusedAddressSettlesImmediately() {
        let log = ProbeLog()
        let vm = viewModel(log: log)

        let devices = vm.merge(raw: [sweepRow("203.0.113.10")])

        #expect(devices.map(\.probesSettled) == [true])
        #expect(log.ips.isEmpty)
    }

    @Test("a re-found row is settled from the carried previous scan before this scan's probe answers")
    func carriedEnrichmentSettlesReFoundRow() {
        let log = ProbeLog()
        let vm = viewModel(log: log)
        let sweep = sweepRow("10.0.0.5")
        _ = vm.merge(raw: [sweep])
        vm.ingestEnrichment(ip: "10.0.0.5", enrichments: [])

        vm.resetForNewScan()
        let rescan = vm.merge(raw: [sweep])

        #expect(rescan.map(\.probesSettled) == [true])
        #expect(log.ips == ["10.0.0.5", "10.0.0.5"])
    }

    @Test("a host whose second address was probed is settled via that address")
    func settledViaSecondAddressOfHost() {
        let log = ProbeLog()
        let vm = viewModel(log: log)
        let lan = bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "10.0.0.10", host: "Mac.local.", port: 22)
        let other = bonjourRow(type: "_http._tcp", name: "Mac", ip: "10.0.0.9", host: "Mac.local.", port: 80)

        _ = vm.merge(raw: [lan])
        let pending = vm.merge(raw: [lan, other])
        #expect(pending.map(\.ipAddress) == ["10.0.0.9"])
        #expect(pending.map(\.probesSettled) == [false])
        #expect(log.ips == ["10.0.0.10", "10.0.0.9"])

        vm.ingestEnrichment(ip: "10.0.0.10", enrichments: [])
        let settled = vm.merge(raw: [lan, other])
        #expect(settled.map(\.probesSettled) == [true])
    }

    @Test("a description-only result stores its data but does not settle the device; the full probe set does")
    func partialResultDoesNotSettle() {
        let vm = viewModel()
        let sweep = sweepRow("10.0.0.5")
        _ = vm.merge(raw: [sweep])
        let description = DeviceEnrichment(mac: nil, manufacturer: "Acme", inferredOS: nil, openPorts: [80], source: .ssdpDescription)

        vm.ingestEnrichment(ip: "10.0.0.5", enrichments: [description], completesProbeSet: false)
        let partial = vm.merge(raw: [sweep])
        #expect(partial.map(\.probesSettled) == [false])
        #expect(partial[0].manufacturer == "Acme")
        #expect(partial[0].openPorts == [80])

        vm.ingestEnrichment(ip: "10.0.0.5", enrichments: [], completesProbeSet: true)
        let full = vm.merge(raw: [sweep])
        #expect(full.map(\.probesSettled) == [true])
        #expect(full[0].manufacturer == "Acme")
    }

    @Test("a partial result in a rescan keeps the carried previous scan's ports and settled state until the full set lands")
    func partialResultKeepsCarriedEnrichment() {
        let vm = viewModel()
        let sweep = sweepRow("10.0.0.5")
        _ = vm.merge(raw: [sweep])
        let banner = DeviceEnrichment(mac: nil, manufacturer: nil, inferredOS: nil, openPorts: [22], source: .portBanner)
        vm.ingestEnrichment(ip: "10.0.0.5", enrichments: [banner], completesProbeSet: true)

        vm.resetForNewScan()
        let description = DeviceEnrichment(mac: nil, manufacturer: "Acme", inferredOS: nil, openPorts: [80], source: .ssdpDescription)
        vm.ingestEnrichment(ip: "10.0.0.5", enrichments: [description], completesProbeSet: false)
        let carried = vm.merge(raw: [sweep])
        #expect(carried.map(\.probesSettled) == [true])
        #expect(carried[0].openPorts == [22, 80])

        vm.ingestEnrichment(ip: "10.0.0.5", enrichments: [], completesProbeSet: true)
        let fresh = vm.merge(raw: [sweep])
        #expect(fresh[0].openPorts == [80])
    }

    @Test("a result landing while a new scan holds the previous list is stored without re-dispatching last scan's probes")
    func resultDuringHoldDoesNotRedispatch() {
        let log = ProbeLog()
        let vm = viewModel(log: log)
        let sweep = sweepRow("10.0.0.5")
        _ = vm.merge(raw: [sweep])
        #expect(log.ips == ["10.0.0.5"])

        vm.resetForNewScan()
        vm.ingestEnrichment(ip: "10.0.0.5", enrichments: [], completesProbeSet: true)
        #expect(log.ips == ["10.0.0.5"])

        // The stored result is picked up by the first merge of the new scan, which probes the address afresh.
        let merged = vm.merge(raw: [sweep])
        #expect(merged.map(\.probesSettled) == [true])
        #expect(log.ips == ["10.0.0.5", "10.0.0.5"])
    }

    @Test("the phone's own row settles once the probe set for its LAN IPv4 answers; its other addresses are never probed")
    func ownRowSettlesViaItsLANAddress() {
        let log = ProbeLog()
        let wifi = ["192.168.8.123", "fe80::aaaa%en0"]
        let own = LocalInterfaces.OwnAddresses(primary: wifi, all: wifi + ["169.254.249.30", "fe80::cccc%anpi0"])
        let vm = NetworkScanViewModel(ownAddresses: { own }, probe: { ip, _ in log.ips.append(ip) })
        let rdlink = bonjourRow(type: "_rdlink._tcp", name: "iPhone", ip: "fe80::cccc%anpi0", host: "iPhone.local.", port: 49152)

        let pending = vm.merge(raw: [rdlink])
        #expect(pending.map(\.ipAddress) == ["192.168.8.123"])
        #expect(pending.map(\.probesSettled) == [false])
        #expect(log.ips == ["192.168.8.123"])

        vm.ingestEnrichment(ip: "192.168.8.123", enrichments: [])
        let settled = vm.merge(raw: [rdlink])
        #expect(settled.map(\.probesSettled) == [true])
        #expect(log.ips == ["192.168.8.123"])
    }

    @Test("carried enrichment is forgotten after three scans without a fresh answer, so a stale result no longer settles the row")
    func carriedEnrichmentExpiresAfterThreeUnseenScans() {
        let vm = viewModel()
        let sweep = sweepRow("10.0.0.5")
        let banner = DeviceEnrichment(mac: nil, manufacturer: nil, inferredOS: nil, openPorts: [22], source: .portBanner)
        _ = vm.merge(raw: [sweep])
        vm.ingestEnrichment(ip: "10.0.0.5", enrichments: [banner])

        for _ in 1...3 { vm.resetForNewScan() }
        let stillCarried = vm.merge(raw: [sweep])
        #expect(stillCarried.map(\.probesSettled) == [true])
        #expect(stillCarried[0].openPorts == [22])

        vm.resetForNewScan()
        let expired = vm.merge(raw: [sweep])
        #expect(expired.map(\.probesSettled) == [false])
        #expect(expired[0].openPorts.isEmpty)
    }

    @Test("a probe result flips probesSettled, so two merges differ and SwiftUI redraws the row")
    func probesSettledTakesPartInEquality() {
        var a = DiscoveredDevice(hostname: "a", ipAddress: "10.0.0.5")
        let b = a
        a.probesSettled = true
        #expect(a != b)
    }
}
