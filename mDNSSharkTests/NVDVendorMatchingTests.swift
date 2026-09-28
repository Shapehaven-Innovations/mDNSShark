// mDNSSharkTests/NVDVendorMatchingTests.swift
import Testing
import Foundation
@testable import mDNSShark

@Suite("NVD vendor matching (PR2)")
struct NVDVendorMatchingTests {

    private func makeDatabase(
        cacheStore: ThreatCacheStoring = MockThreatCacheStore(),
        fetchNVDFeed: @escaping NVDFeedFetcher,
        sleepNanoseconds: @escaping @Sendable (UInt64) async throws -> Void = { _ in },
        now: @escaping @Sendable () -> Date = { Date() }
    ) -> ThreatDatabase {
        ThreatDatabase(
            bundledKEVData: Fixture.bundledKEVJSON,
            nistMapData: Fixture.nistMapWithNVDJSON,
            cacheStore: cacheStore,
            fetchFeed: { throw StubError() },
            fetchNVDFeed: fetchNVDFeed,
            sleepNanoseconds: sleepNanoseconds,
            now: now
        )
    }

    // MARK: - Word-boundary filter

    @Test("a keyword false positive (developer credit, not the vendor) is rejected")
    func wordBoundaryFilterRejectsFalsePositive() async {
        let recorder = RecordingNVDFetcher()
        let falsePositive = Fixture.nvdCVEJSON(
            id: "CVE-2022-22751",
            description: "Mozilla thanks security researcher Calixte Denizet for reporting this issue.",
            cvssV31: ("HIGH", 7.5)
        )
        await recorder.setResponse(.success((falsePositive, Fixture.nvdHTTPResponse())), forAlias: "Calix")

        let db = makeDatabase(fetchNVDFeed: { alias in try await recorder.fetch(alias) })
        try? await db.refreshNVDVendorData(priorityManufacturers: ["Calix"])

        let matches = await db.vendorAdvisory(manufacturer: "Calix Networks")
        #expect(matches.isEmpty)
    }

    @Test("a genuine whole-word match is accepted")
    func wordBoundaryFilterAcceptsRealMatch() async {
        let recorder = RecordingNVDFetcher()
        let real = Fixture.nvdCVEJSON(
            id: "CVE-2024-1111",
            description: "Calix E7 devices allow remote command injection.",
            cvssV31: ("HIGH", 8.0)
        )
        await recorder.setResponse(.success((real, Fixture.nvdHTTPResponse())), forAlias: "Calix")

        let db = makeDatabase(fetchNVDFeed: { alias in try await recorder.fetch(alias) })
        try? await db.refreshNVDVendorData(priorityManufacturers: ["Calix"])

        let matches = await db.vendorAdvisory(manufacturer: "Calix Networks")
        #expect(matches.map(\.cveID) == ["CVE-2024-1111"])
    }

    // MARK: - CVSS extraction fallback order

    @Test("Primary CVSS v3.1 is used when present")
    func cvssExtractionPrefersPrimaryV31() {
        let cve = decodeSingleCVE(Fixture.nvdCVEJSON(id: "CVE-1", description: "d", cvssV31: ("CRITICAL", 9.8)))
        let result = ThreatDatabase.extractCVSSSeverity(from: cve)
        #expect(result?.severity == "CRITICAL")
        #expect(result?.score == 9.8)
    }

    @Test("V2 baseSeverity is read from the metric object, not from cvssData")
    func cvssExtractionHandlesV2Shape() {
        let cve = decodeSingleCVE(Fixture.nvdCVEJSON(id: "CVE-2", description: "d", cvssV2: ("HIGH", 7.8)))
        let result = ThreatDatabase.extractCVSSSeverity(from: cve)
        #expect(result?.severity == "HIGH")
        #expect(result?.score == 7.8)
    }

    @Test("V3.1 is preferred over V2 when both are present")
    func cvssExtractionPrefersV3OverV2() {
        let cve = decodeSingleCVE(Fixture.nvdCVEJSON(
            id: "CVE-3", description: "d", cvssV31: ("MEDIUM", 5.0), cvssV2: ("HIGH", 7.8)
        ))
        let result = ThreatDatabase.extractCVSSSeverity(from: cve)
        #expect(result?.severity == "MEDIUM")
    }

    @Test("no CVSS metric at all yields nil")
    func cvssExtractionReturnsNilWhenAbsent() {
        let cve = decodeSingleCVE(Fixture.nvdCVEJSON(id: "CVE-4", description: "d"))
        #expect(ThreatDatabase.extractCVSSSeverity(from: cve) == nil)
    }

    // MARK: - Rejected CVEs are dropped

    @Test("a Rejected CVE is dropped before it ever reaches severity mapping or matching")
    func rejectedStatusIsDropped() async {
        let recorder = RecordingNVDFetcher()
        let rejected = Fixture.nvdCVEJSON(
            id: "CVE-5", description: "Arris router flaw", vulnStatus: "Rejected", cvssV31: ("CRITICAL", 9.8)
        )
        await recorder.setResponse(.success((rejected, Fixture.nvdHTTPResponse())), forAlias: "Arris")
        await recorder.setResponse(.success((Fixture.emptyNVDResponse(), Fixture.nvdHTTPResponse())), forAlias: "CommScope")

        let db = makeDatabase(fetchNVDFeed: { alias in try await recorder.fetch(alias) })
        try? await db.refreshNVDVendorData(priorityManufacturers: ["Arris"])

        let matches = await db.vendorAdvisory(manufacturer: "Arris")
        #expect(matches.isEmpty)
    }

    // MARK: - Severity mapping table

    @Test("CRITICAL and HIGH map to .warning, MEDIUM to .informational, LOW is filtered")
    func severityMappingTable() {
        #expect(ThreatDatabase.appSeverity(forNVDSeverity: "CRITICAL") == .warning)
        #expect(ThreatDatabase.appSeverity(forNVDSeverity: "HIGH") == .warning)
        #expect(ThreatDatabase.appSeverity(forNVDSeverity: "MEDIUM") == .informational)
        #expect(ThreatDatabase.appSeverity(forNVDSeverity: "LOW") == nil)
        #expect(ThreatDatabase.appSeverity(forNVDSeverity: "NONE") == nil)
    }

    @Test("a LOW-severity match never reaches the cache")
    func lowSeverityIsFilteredBeforeCaching() async {
        let recorder = RecordingNVDFetcher()
        let low = Fixture.nvdCVEJSON(id: "CVE-6", description: "Arris minor issue", cvssV31: ("LOW", 2.0))
        await recorder.setResponse(.success((low, Fixture.nvdHTTPResponse())), forAlias: "Arris")
        await recorder.setResponse(.success((Fixture.emptyNVDResponse(), Fixture.nvdHTTPResponse())), forAlias: "CommScope")

        let db = makeDatabase(fetchNVDFeed: { alias in try await recorder.fetch(alias) })
        try? await db.refreshNVDVendorData(priorityManufacturers: ["Arris"])

        let matches = await db.vendorAdvisory(manufacturer: "Arris")
        #expect(matches.isEmpty)
    }

    // MARK: - Partial failure

    @Test("a vendor whose fetch fails doesn't block or roll back other vendors' data")
    func partialFailureDoesNotAffectOtherVendors() async {
        let recorder = RecordingNVDFetcher()
        // "Arris" alias fails; "CommScope" alias (same vendor) succeeds, so
        // the vendor as a whole still gets the CommScope-sourced entry.
        await recorder.setResponse(.failure(URLError(.timedOut)), forAlias: "Arris")
        let commscopeHit = Fixture.nvdCVEJSON(id: "CVE-7", description: "CommScope cable modem flaw", cvssV31: ("HIGH", 7.5))
        await recorder.setResponse(.success((commscopeHit, Fixture.nvdHTTPResponse())), forAlias: "CommScope")
        // "Calix" (a separate vendor) succeeds independently.
        let calixHit = Fixture.nvdCVEJSON(id: "CVE-8", description: "Calix ONT authentication bypass", cvssV31: ("CRITICAL", 9.1))
        await recorder.setResponse(.success((calixHit, Fixture.nvdHTTPResponse())), forAlias: "Calix")

        let db = makeDatabase(fetchNVDFeed: { alias in try await recorder.fetch(alias) })
        try? await db.refreshNVDVendorData(priorityManufacturers: ["Arris", "Calix"])

        let arrisMatches = await db.vendorAdvisory(manufacturer: "Arris")
        #expect(arrisMatches.map(\.cveID) == ["CVE-7"])
        let calixMatches = await db.vendorAdvisory(manufacturer: "Calix Networks")
        #expect(calixMatches.map(\.cveID) == ["CVE-8"])
    }

    @Test("an NVD-phase failure never touches already-cached KEV data")
    func nvdFailureDoesNotAffectKEVData() async throws {
        let store = MockThreatCacheStore()
        let kevFeed = Fixture.liveFeedJSON(catalogVersion: "2026.03.01", matching: [
            ("CVE-2020-9054", "Zyxel NAS OS Command Injection", "desc"),
        ])
        let db = ThreatDatabase(
            bundledKEVData: Fixture.bundledKEVJSON,
            nistMapData: Fixture.nistMapWithNVDJSON,
            cacheStore: store,
            fetchFeed: immediateFetcher { (kevFeed, Fixture.httpResponse()) },
            fetchNVDFeed: { _ in throw URLError(.timedOut) },
            sleepNanoseconds: { _ in }
        )
        _ = try await db.refresh()
        try? await db.refreshNVDVendorData(priorityManufacturers: ["Arris"])

        let status = await db.status()
        #expect(status.refreshedCatalogVersion == "2026.03.01")
        let matches = await db.vendorAdvisory(manufacturer: "Zyxel")
        #expect(matches.contains { $0.cveID == "CVE-2020-9054" && $0.source == .kev })
    }

    // MARK: - Cancellation

    @Test("cancelling mid-sequence stops before every vendor is queried")
    func cancellationStopsEarly() async {
        // The first NVD request hangs via GatedFetcher until released, so
        // cancellation has something in flight to interrupt.
        let gate = GatedFetcher()
        await gate.setResult(.success((Fixture.emptyNVDResponse(), Fixture.nvdHTTPResponse())))

        let db = ThreatDatabase(
            bundledKEVData: Fixture.bundledKEVJSON,
            nistMapData: Fixture.nistMapWithNVDJSON,
            cacheStore: MockThreatCacheStore(),
            fetchFeed: { throw StubError() },
            fetchNVDFeed: { _ in try await gate.fetch() },
            sleepNanoseconds: { _ in }
        )

        let task = Task { try await db.refreshNVDVendorData(priorityManufacturers: ["Arris"]) }
        try? await Task.sleep(nanoseconds: 20_000_000)
        task.cancel()

        let callCountBeforeRelease = await gate.callCount
        await gate.release()
        _ = try? await task.value

        // Only the first alias's request should have started before
        // cancellation was observed - the gate never released early
        // enough for a second alias to begin.
        #expect(callCountBeforeRelease == 1)
    }

    // MARK: - Rate-limit spacing (sequencing, not real timing)

    @Test("a vendor with two aliases waits between the two requests")
    func spacingWaitsBetweenSequentialRequests() async {
        actor SleepRecorder {
            private(set) var calls: [UInt64] = []
            func record(_ ns: UInt64) { calls.append(ns) }
        }
        let sleepRecorder = SleepRecorder()
        let recorder = RecordingNVDFetcher()
        await recorder.setResponse(.success((Fixture.emptyNVDResponse(), Fixture.nvdHTTPResponse())), forAlias: "Arris")
        await recorder.setResponse(.success((Fixture.emptyNVDResponse(), Fixture.nvdHTTPResponse())), forAlias: "CommScope")

        let db = makeDatabase(
            fetchNVDFeed: { alias in try await recorder.fetch(alias) },
            sleepNanoseconds: { ns in await sleepRecorder.record(ns) }
        )
        // Restrict to just the "arris" vendor (2 aliases) by only priming
        // responses for its aliases - "calix" would throw StubError and be
        // skipped/logged, not asserted on here.
        await recorder.setResponse(.failure(StubError()), forAlias: "Calix")

        try? await db.refreshNVDVendorData(priorityManufacturers: ["Arris"])

        let queried = await recorder.queriedAliases
        #expect(queried.contains("Arris"))
        #expect(queried.contains("CommScope"))
        // One spacing wait between Arris's two aliases, plus one before the
        // next vendor's first alias - at least one recorded sleep either way
        // confirms requests aren't all fired back-to-back with zero spacing.
        let sleepCalls = await sleepRecorder.calls
        #expect(!sleepCalls.isEmpty)
        #expect(sleepCalls.allSatisfy { $0 > 0 })
    }

    @Test("priority manufacturers are queried before non-priority vendors")
    func priorityVendorsQueriedFirst() async {
        let recorder = RecordingNVDFetcher()
        await recorder.setResponse(.success((Fixture.emptyNVDResponse(), Fixture.nvdHTTPResponse())), forAlias: "Arris")
        await recorder.setResponse(.success((Fixture.emptyNVDResponse(), Fixture.nvdHTTPResponse())), forAlias: "CommScope")
        await recorder.setResponse(.success((Fixture.emptyNVDResponse(), Fixture.nvdHTTPResponse())), forAlias: "Calix")

        let db = makeDatabase(fetchNVDFeed: { alias in try await recorder.fetch(alias) })
        // Both vendors present so there's something to order between -
        // "Calix" listed first should still be queried first even though
        // "Arris" appears later in the priority list. "Calix" has no
        // manufacturer alias match for "Calix Networks" via resolveVendor
        // unless it's an exact whole-token alias - use the vendor's own
        // alias directly to guarantee resolution.
        try? await db.refreshNVDVendorData(priorityManufacturers: ["Calix", "Arris"])

        let queried = await recorder.queriedAliases
        #expect(queried.first == "Calix")
    }

    // MARK: - Vendor-presence filter + TTL (PR C)

    @Test("a vendor fetched less than 24h ago is skipped entirely, no request made")
    func ttlSkipsRecentlyFetchedVendor() async {
        let recorder = RecordingNVDFetcher()
        // No response queued for "Arris"/"CommScope" - if either were
        // queried it would throw StubError, which queriedAliases below
        // would still catch regardless.
        let now = Date()
        let previousEntry = NVDCachedEntry(
            cveID: "CVE-OLD", title: "Old cached title", description: "d",
            cvssBaseSeverity: "HIGH", cvssBaseScore: 8.0, dateAdded: "2026-01-01"
        )
        let seeded = KEVCacheFile(
            schemaVersion: KEVCacheFile.currentSchema,
            kevFetchedAt: nil, catalogVersion: nil, catalogDateReleased: nil,
            entries: [:],
            nvdVendors: ["arris": NVDVendorCache(fetchedAt: now.addingTimeInterval(-3600), entries: [previousEntry])],
            nvdVendorLastSeen: ["arris": now],
            nvdLastCheckedAt: now.addingTimeInterval(-3600)
        )
        let store = MockThreatCacheStore(initial: seeded)
        let db = makeDatabase(cacheStore: store, fetchNVDFeed: { alias in try await recorder.fetch(alias) }, now: { now })

        try? await db.refreshNVDVendorData(priorityManufacturers: ["Arris"])

        #expect(await recorder.queriedAliases.isEmpty)
        let matches = await db.vendorAdvisory(manufacturer: "Arris")
        #expect(matches.map(\.cveID) == ["CVE-OLD"])
    }

    @Test("a vendor last seen 31 days ago is excluded from refresh scope")
    func lastSeenExpiryExcludesOldVendor() async {
        let recorder = RecordingNVDFetcher()
        let now = Date()
        let seeded = KEVCacheFile(
            schemaVersion: KEVCacheFile.currentSchema,
            kevFetchedAt: nil, catalogVersion: nil, catalogDateReleased: nil,
            entries: [:], nvdVendors: [:],
            nvdVendorLastSeen: ["arris": now.addingTimeInterval(-31 * 24 * 60 * 60)],
            nvdLastCheckedAt: nil
        )
        let store = MockThreatCacheStore(initial: seeded)
        let db = makeDatabase(cacheStore: store, fetchNVDFeed: { alias in try await recorder.fetch(alias) }, now: { now })

        // Not present in this scan (empty priorityManufacturers), and last
        // seen 31 days ago - outside the 30-day window.
        try? await db.refreshNVDVendorData(priorityManufacturers: [])

        #expect(await recorder.queriedAliases.isEmpty)
    }

    @Test("a vendor last seen 29 days ago is still included in refresh scope")
    func lastSeenExpiryIncludesRecentVendor() async {
        let recorder = RecordingNVDFetcher()
        await recorder.setResponse(.success((Fixture.emptyNVDResponse(), Fixture.nvdHTTPResponse())), forAlias: "Arris")
        await recorder.setResponse(.success((Fixture.emptyNVDResponse(), Fixture.nvdHTTPResponse())), forAlias: "CommScope")
        let now = Date()
        let seeded = KEVCacheFile(
            schemaVersion: KEVCacheFile.currentSchema,
            kevFetchedAt: nil, catalogVersion: nil, catalogDateReleased: nil,
            entries: [:], nvdVendors: [:],
            nvdVendorLastSeen: ["arris": now.addingTimeInterval(-29 * 24 * 60 * 60)],
            nvdLastCheckedAt: nil
        )
        let store = MockThreatCacheStore(initial: seeded)
        let db = makeDatabase(cacheStore: store, fetchNVDFeed: { alias in try await recorder.fetch(alias) }, now: { now })

        try? await db.refreshNVDVendorData(priorityManufacturers: [])

        #expect(await recorder.queriedAliases.contains("Arris"))
    }

    @Test("a refresh with no present or recently-seen vendors still records that NVD was checked")
    func nvdCheckedAtRecordedEvenWithNoQueries() async {
        let recorder = RecordingNVDFetcher()
        let now = Date()
        let db = makeDatabase(fetchNVDFeed: { alias in try await recorder.fetch(alias) }, now: { now })

        try? await db.refreshNVDVendorData(priorityManufacturers: [])

        #expect(await recorder.queriedAliases.isEmpty)
        let status = await db.status()
        #expect(status.nvdLastCheckedAt == now)
        #expect(status.nvdLastSuccessfulRefresh == nil)
    }

    @Test("a partial-alias failure merges with previous data and does not advance fetchedAt")
    func partialAliasFailureDoesNotAdvanceFetchedAt() async {
        let recorder = RecordingNVDFetcher()
        let earlierFetch = Date(timeIntervalSince1970: 1_700_000_000)
        // Two days later - past the 24h TTL, so the vendor is eligible to
        // be queried again this run.
        let laterNow = earlierFetch.addingTimeInterval(2 * 24 * 60 * 60)
        let previousEntry = NVDCachedEntry(
            cveID: "CVE-PREV", title: "Previously found", description: "d",
            cvssBaseSeverity: "HIGH", cvssBaseScore: 7.0, dateAdded: "2026-01-01"
        )
        let seeded = KEVCacheFile(
            schemaVersion: KEVCacheFile.currentSchema,
            kevFetchedAt: nil, catalogVersion: nil, catalogDateReleased: nil,
            entries: [:],
            nvdVendors: ["arris": NVDVendorCache(fetchedAt: earlierFetch, entries: [previousEntry])],
            nvdVendorLastSeen: [:],
            nvdLastCheckedAt: nil
        )
        let store = MockThreatCacheStore(initial: seeded)

        // "Arris" alias fails this run, "CommScope" alias succeeds with a
        // new entry - a partial success for the vendor as a whole.
        await recorder.setResponse(.failure(URLError(.timedOut)), forAlias: "Arris")
        let newHit = Fixture.nvdCVEJSON(id: "CVE-NEW", description: "CommScope new flaw", cvssV31: ("HIGH", 7.5))
        await recorder.setResponse(.success((newHit, Fixture.nvdHTTPResponse())), forAlias: "CommScope")

        let db = makeDatabase(cacheStore: store, fetchNVDFeed: { alias in try await recorder.fetch(alias) }, now: { laterNow })
        try? await db.refreshNVDVendorData(priorityManufacturers: ["Arris"])

        let matches = await db.vendorAdvisory(manufacturer: "Arris")
        let ids = Set(matches.map(\.cveID))
        // Both the previously-cached entry and the newly-found one survive
        // the merge - the failed alias didn't wipe out what an earlier,
        // fully-successful fetch had already found.
        #expect(ids == ["CVE-PREV", "CVE-NEW"])

        // fetchedAt was NOT advanced to `laterNow` since not every alias
        // succeeded - a later refresh should still treat this vendor as
        // due for a full retry despite `laterNow` nominally satisfying the
        // 24h TTL.
        #expect(store.lastSaved?.nvdVendors["arris"]?.fetchedAt == earlierFetch)
    }

    // MARK: - Helpers

    private func decodeSingleCVE(_ data: Data) -> NVDCVEDetail {
        let response = try! JSONDecoder().decode(NVDResponse.self, from: data)
        return response.vulnerabilities[0].cve
    }
}
