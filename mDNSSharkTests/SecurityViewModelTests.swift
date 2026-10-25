// mDNSSharkTests/SecurityViewModelTests.swift
import Testing
import Foundation
@testable import mDNSShark

@MainActor
@Suite("SecurityViewModel threat-data refresh")
struct SecurityViewModelTests {

    private func makeDevice(manufacturer: String? = nil) -> DiscoveredDevice {
        DiscoveredDevice(
            hostname: "test-nas",
            ipAddress: "192.168.1.50",
            manufacturer: manufacturer,
            bonjourServices: [
                BonjourService(serviceType: "_ftp._tcp", serviceName: "test-nas", port: 21)
            ]
        )
    }

    private func makeViewModel(
        cacheStore: ThreatCacheStoring = MockThreatCacheStore(),
        fetchFeed: @escaping KEVFeedFetcher = { throw StubError() },
        isTunnelActive: @escaping @Sendable () async -> Bool = { false }
    ) -> SecurityViewModel {
        let db = ThreatDatabase(
            bundledKEVData: Fixture.bundledKEVJSON,
            nistMapData: Fixture.nistMapJSON,
            cacheStore: cacheStore,
            fetchFeed: fetchFeed
        )
        return SecurityViewModel(threatDatabase: db, isTunnelActive: isTunnelActive)
    }

    // 13. Capture active: fetcher never called, .captureActive, isRefreshing resets
    @Test("refresh is skipped entirely while the capture tunnel is active")
    func skipsRefreshDuringCapture() async throws {
        // Pre-released with its default `.failure(StubError())` result, so a
        // call would throw immediately; the assertion is that none happens.
        let gate = GatedFetcher()
        await gate.release()
        let vm = makeViewModel(
            fetchFeed: { try await gate.fetch() },
            isTunnelActive: { true }
        )
        vm.startThreatDataRefresh()
        try await waitUntil { !vm.isRefreshing }
        #expect(await gate.callCount == 0)
        #expect(vm.refreshError == .captureActive)
        #expect(!vm.isRefreshing)
    }

    // 14. Double tap calls the fetcher once
    @Test("a double tap only triggers one fetch")
    func doubleTapFetchesOnce() async throws {
        let gate = GatedFetcher()
        await gate.setResult(.success((Fixture.liveFeedJSON(matching: []), Fixture.httpResponse())))
        let vm = makeViewModel(fetchFeed: { try await gate.fetch() })

        vm.startThreatDataRefresh()
        vm.startThreatDataRefresh()
        try await Task.sleep(nanoseconds: 20_000_000)
        #expect(await gate.callCount == 1)

        await gate.release()
        try await waitUntil { !vm.isRefreshing }
    }

    // 15. Success re-runs assess() with the refreshed data
    @Test("a successful refresh re-assesses the last-scanned devices")
    func successRerunsAssess() async throws {
        // Bundled data only has CVE-2023-3333 for ASUS; the refresh adds a
        // second ASUS-claimed CVE the bundle never had.
        let feed = Fixture.liveFeedJSON(catalogVersion: "2026.03.01", matching: [
            ("CVE-2023-3333", "ASUS Router RCE", "desc"),
            ("CVE-2026-4444", "ASUS New Bug", "new desc"),
        ], vendorProjects: ["ASUS", "ASUS"])
        let vm = makeViewModel(fetchFeed: immediateFetcher { (feed, Fixture.httpResponse()) })

        let device = makeDevice(manufacturer: "ASUS")
        await vm.assess(devices: [device])
        // Before refresh: only the bundled CVE is known.
        let before = vm.findings.first { $0.source == .vendorAdvisory }
        let beforeIDs = before?.cveTiers.flatMap(\.cveIDs) ?? []
        #expect(beforeIDs.contains("CVE-2023-3333") == true)
        #expect(beforeIDs.contains("CVE-2026-4444") == false)

        vm.startThreatDataRefresh()
        try await waitUntil { !vm.isRefreshing }

        let after = vm.findings.first { $0.source == .vendorAdvisory }
        let afterIDs = after?.cveTiers.flatMap(\.cveIDs) ?? []
        #expect(afterIDs.contains("CVE-2023-3333") == true)
        #expect(afterIDs.contains("CVE-2026-4444") == true)
    }

    // 16. Failure leaves threatDataStatus unchanged and resets isRefreshing
    @Test("a failed refresh leaves threatDataStatus unchanged")
    func failureLeavesStatusUnchanged() async throws {
        let vm = makeViewModel(fetchFeed: { throw URLError(.notConnectedToInternet) })
        await vm.loadThreatDataStatus()
        let before = vm.threatDataStatus

        vm.startThreatDataRefresh()
        try await waitUntil { !vm.isRefreshing }

        #expect(vm.threatDataStatus == before)
        #expect(vm.refreshError == .network)
        #expect(!vm.isRefreshing)
    }

    // 17. cancelThreatDataRefresh() during a gated fetch gives .cancelledByCapture, no save
    @Test("cancelling mid-fetch surfaces .cancelledByCapture and saves nothing")
    func cancelMidFetch() async throws {
        let gate = GatedFetcher()
        let store = MockThreatCacheStore()
        let vm = makeViewModel(cacheStore: store, fetchFeed: { try await gate.fetch() })

        vm.startThreatDataRefresh()
        try await Task.sleep(nanoseconds: 20_000_000)
        vm.cancelThreatDataRefresh()
        try await waitUntil { !vm.isRefreshing }

        #expect(vm.refreshError == .cancelledByCapture)
        #expect(store.lastSaved == nil)
    }

    // Bug #1 regression: a device with a Bonjour service AND a
    // vendor-matched manufacturer must never get a .critical finding from
    // the manufacturer match - only the vendor-advisory path can produce a
    // manufacturer-driven finding, and it's always .warning, grouped into
    // exactly one finding regardless of how many CVEs or services matched.
    @Test("a vendor-matched manufacturer never produces a critical finding, even with a matching service")
    func manufacturerMatchNeverCritical() async throws {
        let vm = makeViewModel()
        let device = DiscoveredDevice(
            hostname: "asus-router",
            ipAddress: "192.168.1.1",
            manufacturer: "ASUSTek COMPUTER INC.",
            bonjourServices: [
                BonjourService(serviceType: "_ftp._tcp", serviceName: "asus-router", port: 21)
            ]
        )
        await vm.assess(devices: [device])

        let vendorFindings = vm.findings.filter { $0.source == .vendorAdvisory }
        #expect(vendorFindings.count == 1)
        #expect(vendorFindings.allSatisfy { $0.severity == .warning })
        #expect(!vm.findings.contains { $0.source == .vendorAdvisory && $0.severity == .critical })
    }

    // Issue #4: only cleartext-credential open ports are critical.
    @Test("an open VNC port is a warning, not critical")
    func vncOpenPortIsWarning() async {
        let vm = makeViewModel()
        let device = DiscoveredDevice(hostname: "mac-mini", ipAddress: "192.168.1.60", openPorts: [5900])
        await vm.assess(devices: [device])
        let vnc = vm.findings.first { $0.source == .portRule && $0.title == "VNC Exposed" }
        #expect(vnc?.severity == .warning)
        #expect(vm.criticalFindings.isEmpty)
    }

    @Test("an open Telnet port is critical")
    func telnetOpenPortIsCritical() async {
        let vm = makeViewModel()
        let device = DiscoveredDevice(hostname: "old-switch", ipAddress: "192.168.1.61", openPorts: [23])
        await vm.assess(devices: [device])
        let telnet = vm.findings.first { $0.source == .portRule && $0.title == "Telnet Exposed" }
        #expect(telnet?.severity == .critical)
    }

    @Test("a _rfb._tcp advertisement is informational")
    func rfbAdvertIsInformational() async {
        let vm = makeViewModel()
        let device = DiscoveredDevice(
            hostname: "mac-mini", ipAddress: "192.168.1.62",
            bonjourServices: [BonjourService(serviceType: "_rfb._tcp", serviceName: "mac-mini", port: 5900)]
        )
        await vm.assess(devices: [device])
        let rfb = vm.findings.first { $0.source == .bonjourRule }
        #expect(rfb?.severity == .informational)
    }

    @Test("a device with only Bonjour advertisements is not counted vulnerable")
    func bonjourOnlyDeviceNotVulnerable() async {
        let vm = makeViewModel()
        let device = DiscoveredDevice(
            hostname: "nas", ipAddress: "192.168.1.63",
            bonjourServices: [
                BonjourService(serviceType: "_telnet._tcp", serviceName: "nas", port: 23),
                BonjourService(serviceType: "_ftp._tcp", serviceName: "nas", port: 21),
                BonjourService(serviceType: "_ssh._tcp", serviceName: "nas", port: 22),
                BonjourService(serviceType: "_smb._tcp", serviceName: "nas", port: 445)
            ]
        )
        await vm.assess(devices: [device])
        #expect(!vm.findings.isEmpty)
        #expect(vm.vulnerableDeviceCount == 0)
    }
}

/// Polls a MainActor condition until it's true or a short timeout elapses,
/// since these tests drive real `Task`s off the gate/fetch closures rather
/// than controlling a scheduler directly.
@MainActor
private func waitUntil(timeout: TimeInterval = 2.0, _ condition: () -> Bool) async throws {
    let deadline = Date().addingTimeInterval(timeout)
    while !condition() {
        if Date() > deadline {
            Issue.record("Timed out waiting for condition")
            return
        }
        try await Task.sleep(nanoseconds: 5_000_000)
    }
}
