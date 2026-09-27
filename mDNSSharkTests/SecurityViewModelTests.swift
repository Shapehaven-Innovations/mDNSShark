// mDNSSharkTests/SecurityViewModelTests.swift
import Testing
import Foundation
@testable import mDNSShark

@MainActor
@Suite("SecurityViewModel threat-data refresh")
struct SecurityViewModelTests {

    private func makeDevice() -> DiscoveredDevice {
        DiscoveredDevice(
            hostname: "test-nas",
            ipAddress: "192.168.1.50",
            manufacturer: nil,
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
        var fetchCalled = false
        let vm = makeViewModel(
            fetchFeed: {
                fetchCalled = true
                throw StubError()
            },
            isTunnelActive: { true }
        )
        vm.startThreatDataRefresh()
        try await waitUntil { !vm.isRefreshing }
        #expect(!fetchCalled)
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
        let feed = Fixture.liveFeedJSON(catalogVersion: "2026.03.01", matching: [
            ("CVE-2011-2523", "vsftpd Backdoor (refreshed)", "desc"),
        ])
        let vm = makeViewModel(fetchFeed: immediateFetcher { (feed, Fixture.httpResponse()) })

        let device = makeDevice()
        await vm.assess(devices: [device])
        // Before refresh: CVE-2011-2523 has curated (NIST) text, not CISA.
        #expect(vm.findings.contains { $0.cveID == "CVE-2011-2523" && $0.source == .nist })

        vm.startThreatDataRefresh()
        try await waitUntil { !vm.isRefreshing }

        #expect(vm.findings.contains { $0.cveID == "CVE-2011-2523" && $0.source == .cisaKEV })
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
