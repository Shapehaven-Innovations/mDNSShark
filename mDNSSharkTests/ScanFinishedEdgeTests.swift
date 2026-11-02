import Testing
import Foundation
import Combine
@testable import mDNSShark

@MainActor
@Suite("Scan end edge and device status")
struct ScanFinishedEdgeTests {
    @Test("only a real true to false transition with the scanner idle is a scan end")
    func edge() {
        #expect(NetworkScanViewModel.isScanEndEdge(wasScanning: true, scanning: false, scannerScanning: false))
        #expect(!NetworkScanViewModel.isScanEndEdge(wasScanning: false, scanning: false, scannerScanning: false)) // initial seed
        #expect(!NetworkScanViewModel.isScanEndEdge(wasScanning: true, scanning: false, scannerScanning: true))   // restart
        #expect(!NetworkScanViewModel.isScanEndEdge(wasScanning: false, scanning: true, scannerScanning: true))
    }

    @Test("own address keys strip scope and lowercase")
    func ownKeys() {
        let vm = NetworkScanViewModel(ownAddresses: { ["192.168.1.20", "FE80::1%en0"] }, probe: { _, _ in })
        #expect(vm.ownAddressMatchKeys == ["192.168.1.20", "fe80::1"])
    }

    @Test("status(of:) agrees with statusCounts and keeps unprobed devices out of secure")
    func statusOf() {
        let db = ThreatDatabase(bundledKEVData: Fixture.bundledKEVJSON, nistMapData: Fixture.nistMapJSON,
                                cacheStore: MockThreatCacheStore(), fetchFeed: { throw StubError() })
        let vm = SecurityViewModel(threatDatabase: db, isTunnelActive: { false })
        let ftp = DiscoveredDevice(hostname: "ftp", ipAddress: "192.168.1.50", openPorts: [21], probesSettled: true)
        let clean = DiscoveredDevice(hostname: "clean", ipAddress: "192.168.1.51", probesSettled: true)
        let busy = DiscoveredDevice(hostname: "busy", ipAddress: "192.168.1.52", probesSettled: false)
        vm.assess(devices: [ftp, clean, busy])
        #expect(vm.status(of: ftp) == .critical)
        #expect(vm.status(of: clean) == .secure)
        #expect(vm.status(of: busy) == .pending)
        let counts = vm.statusCounts(among: [ftp, clean, busy])
        #expect(counts == [.critical: 1, .secure: 1, .pending: 1])
    }

    @Test("scanFinished fires once, after the held-rows block, and not on the initial false or a restart")
    func emitsOnceAfterFinalApply() async throws {
        let vm = NetworkScanViewModel(ownAddresses: { [] }, probe: { _, _ in })
        var holdingAtEmission: [Bool] = []
        let sub = vm.scanFinished.sink { holdingAtEmission.append(vm.holdingUntilFirstResult) }
        defer { sub.cancel() }

        try await Task.sleep(for: .milliseconds(100))
        #expect(holdingAtEmission.isEmpty) // initial false

        vm.holdingUntilFirstResult = true
        vm.scanner.isScanning = true
        try await Task.sleep(for: .milliseconds(100))
        #expect(holdingAtEmission.isEmpty) // true edge

        vm.scanner.isScanning = false
        vm.scanner.isScanning = true // restart before the sink runs
        try await Task.sleep(for: .milliseconds(100))
        #expect(holdingAtEmission.isEmpty)

        vm.scanner.isScanning = false
        try await Task.sleep(for: .milliseconds(100))
        #expect(holdingAtEmission == [false]) // one emission, after the final apply cleared the hold
    }
}
