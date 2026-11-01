// mDNSSharkTests/SecureCountTests.swift
import Testing
import Foundation
@testable import mDNSShark

@MainActor
@Suite("Header secure count covers settled devices only")
struct SecureCountTests {

    private func makeViewModel() -> SecurityViewModel {
        let db = ThreatDatabase(bundledKEVData: Fixture.bundledKEVJSON, nistMapData: Fixture.nistMapJSON,
                                cacheStore: MockThreatCacheStore(), fetchFeed: { throw StubError() })
        return SecurityViewModel(threatDatabase: db, isTunnelActive: { false })
    }

    private func device(_ host: String, ip: String, openPorts: [Int] = [], settled: Bool) -> DiscoveredDevice {
        var d = DiscoveredDevice(hostname: host, ipAddress: ip, openPorts: openPorts)
        d.probesSettled = settled
        return d
    }

    @Test("a device whose probes have not settled is not counted as secure")
    func pendingIsNotSecure() {
        let vm = makeViewModel()
        let first = device("a", ip: "192.168.1.10", settled: true)
        let second = device("b", ip: "192.168.1.11", settled: false)
        vm.assess(devices: [first, second])
        #expect(vm.secureDeviceCount(among: [first, second]) == 1)

        var settledSecond = second
        settledSecond.probesSettled = true
        vm.assess(devices: [first, settledSecond])
        #expect(vm.secureDeviceCount(among: [first, settledSecond]) == 2)
    }

    @Test("the count follows the device row, not whether assess ran")
    func countNeedsNoAssessment() {
        let vm = makeViewModel()
        let settled = device("a", ip: "192.168.1.10", settled: true)
        #expect(vm.secureDeviceCount(among: [settled]) == 1)
    }

    @Test("a settled vulnerable device is not counted as secure")
    func vulnerableIsNotSecure() {
        let vm = makeViewModel()
        let telnet = device("cam", ip: "192.168.1.20", openPorts: [23], settled: true)
        vm.assess(devices: [telnet])
        #expect(vm.vulnerableDeviceCount == 1)
        #expect(vm.secureDeviceCount(among: [telnet]) == 0)
    }
}
