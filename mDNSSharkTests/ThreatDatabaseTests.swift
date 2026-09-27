// mDNSSharkTests/ThreatDatabaseTests.swift
import Testing
import Foundation
@testable import mDNSShark

@Suite("ThreatDatabase")
struct ThreatDatabaseTests {

    private func makeDatabase(
        cacheStore: ThreatCacheStoring = MockThreatCacheStore(),
        fetchFeed: @escaping KEVFeedFetcher = { throw StubError() },
        now: @escaping @Sendable () -> Date = { Date() }
    ) -> ThreatDatabase {
        ThreatDatabase(
            bundledKEVData: Fixture.bundledKEVJSON,
            nistMapData: Fixture.nistMapJSON,
            cacheStore: cacheStore,
            fetchFeed: fetchFeed,
            now: now
        )
    }

    // 1. Bundled-only lookup precedence
    @Test("bundled KEV entry gives CISA attribution")
    func bundledKEVGivesCISA() async {
        let db = makeDatabase()
        let results = await db.lookup(manufacturer: nil, serviceType: "_ftp._tcp", port: nil)
        let kevResult = results.first { $0.cveID == "CVE-2020-9054" }
        #expect(kevResult?.source == .cisa)
        #expect(kevResult?.vulnerabilityName == "Zyxel NAS OS Command Injection")
    }

    @Test("non-KEV mapped CVE with curated text gives NIST attribution with curated copy")
    func curatedTextGivesNIST() async {
        let db = makeDatabase()
        let results = await db.lookup(manufacturer: nil, serviceType: "_ftp._tcp", port: nil)
        let curated = results.first { $0.cveID == "CVE-2011-2523" }
        #expect(curated?.source == .nist)
        #expect(curated?.vulnerabilityName == "vsftpd 2.3.4 Backdoor")
    }

    @Test("mapped CVE with neither KEV nor curated text falls back to generic title")
    func fallsBackToGenericTitle() async {
        let db = makeDatabase()
        let results = await db.lookup(manufacturer: "ASUS", serviceType: nil, port: nil)
        let fallback = results.first { $0.cveID == "CVE-2023-39238" }
        #expect(fallback?.source == .nist)
        #expect(fallback?.vulnerabilityName == "ASUS Known Vulnerability")
    }

    // 2/3/4. Refresh promotes, keeps fallback, overlays text
    @Test("successful refresh promotes a previously-NIST CVE to CISA")
    func refreshPromotesToCISA() async throws {
        let store = MockThreatCacheStore()
        let feed = Fixture.liveFeedJSON(catalogVersion: "2026.03.01", matching: [
            ("CVE-2020-9054", "Zyxel NAS OS Command Injection (updated)", "updated desc"),
            ("CVE-2011-2523", "vsftpd 2.3.4 Backdoor (CISA)", "CISA-sourced desc"),
        ])
        let db = makeDatabase(cacheStore: store, fetchFeed: immediateFetcher {
            (feed, Fixture.httpResponse())
        })
        _ = try await db.refresh()
        let results = await db.lookup(manufacturer: nil, serviceType: "_ftp._tcp", port: nil)
        let promoted = results.first { $0.cveID == "CVE-2011-2523" }
        #expect(promoted?.source == .cisa)
        #expect(promoted?.vulnerabilityName == "vsftpd 2.3.4 Backdoor (CISA)")
    }

    @Test("a bundled KEV CVE absent from a newer feed keeps its bundled CISA attribution")
    func refreshKeepsBundledWhenAbsentFromFeed() async throws {
        let store = MockThreatCacheStore()
        // Feed doesn't include CVE-2020-9054 at all.
        let feed = Fixture.liveFeedJSON(catalogVersion: "2026.03.01", matching: [
            ("CVE-2011-2523", "vsftpd Backdoor", "desc"),
        ])
        let db = makeDatabase(cacheStore: store, fetchFeed: immediateFetcher {
            (feed, Fixture.httpResponse())
        })
        _ = try await db.refresh()
        let results = await db.lookup(manufacturer: nil, serviceType: "_ftp._tcp", port: nil)
        let stillThere = results.first { $0.cveID == "CVE-2020-9054" }
        #expect(stillThere?.source == .cisa)
        #expect(stillThere?.vulnerabilityName == "Zyxel NAS OS Command Injection")
    }

    @Test("refresh overlays text for a bundled KEV CVE the feed also lists")
    func refreshOverlaysBundledText() async throws {
        let store = MockThreatCacheStore()
        let feed = Fixture.liveFeedJSON(catalogVersion: "2026.03.01", matching: [
            ("CVE-2020-9054", "Zyxel NAS - renamed", "renamed desc"),
        ])
        let db = makeDatabase(cacheStore: store, fetchFeed: immediateFetcher {
            (feed, Fixture.httpResponse())
        })
        _ = try await db.refresh()
        let results = await db.lookup(manufacturer: nil, serviceType: "_ftp._tcp", port: nil)
        let updated = results.first { $0.cveID == "CVE-2020-9054" }
        #expect(updated?.vulnerabilityName == "Zyxel NAS - renamed")
    }

    // 5. Only the referenced subset is saved
    @Test("refresh only persists CVEs the map actually references")
    func refreshPersistsOnlyReferencedSubset() async throws {
        let store = MockThreatCacheStore()
        let feed = Fixture.liveFeedJSON(catalogVersion: "2026.03.01", matching: [
            ("CVE-2020-9054", "Zyxel", "desc"),
            ("CVE-2011-2523", "vsftpd", "desc"),
            ("CVE-2023-39238", "ASUS", "desc"),
        ])
        let db = makeDatabase(cacheStore: store, fetchFeed: immediateFetcher {
            (feed, Fixture.httpResponse())
        })
        _ = try await db.refresh()
        let savedKeys = Set(store.lastSaved?.entries.keys ?? [])
        #expect(savedKeys == ["CVE-2020-9054", "CVE-2011-2523", "CVE-2023-39238"])
    }

    // 6. Failure paths leave state untouched, nothing saved
    @Test("network failure throws .network and saves nothing")
    func networkFailureThrowsNetwork() async throws {
        let store = MockThreatCacheStore()
        let db = makeDatabase(cacheStore: store, fetchFeed: immediateFetcher {
            throw URLError(.notConnectedToInternet)
        })
        await #expect(throws: ThreatRefreshError.network(.notConnectedToInternet)) {
            _ = try await db.refresh()
        }
        #expect(store.lastSaved == nil)
    }

    @Test("HTTP 500 throws .badStatus(500)")
    func httpErrorThrowsBadStatus() async throws {
        let store = MockThreatCacheStore()
        let db = makeDatabase(cacheStore: store, fetchFeed: immediateFetcher {
            (Data(), Fixture.httpResponse(status: 500))
        })
        await #expect(throws: ThreatRefreshError.badStatus(500)) {
            _ = try await db.refresh()
        }
        #expect(store.lastSaved == nil)
    }

    @Test("an HTML captive-portal body throws .undecodable")
    func htmlBodyThrowsUndecodable() async throws {
        let store = MockThreatCacheStore()
        let db = makeDatabase(cacheStore: store, fetchFeed: immediateFetcher {
            ("<html>captive portal</html>".data(using: .utf8)!, Fixture.httpResponse())
        })
        await #expect(throws: ThreatRefreshError.undecodable) {
            _ = try await db.refresh()
        }
        #expect(store.lastSaved == nil)
    }

    @Test("a short feed throws .implausibleFeed")
    func shortFeedThrowsImplausible() async throws {
        let store = MockThreatCacheStore()
        let feed = Fixture.liveFeedJSON(matching: [("CVE-2020-9054", "Zyxel", "desc")], paddingCount: 8)
        let db = makeDatabase(cacheStore: store, fetchFeed: immediateFetcher {
            (feed, Fixture.httpResponse())
        })
        await #expect(throws: ThreatRefreshError.implausibleFeed) {
            _ = try await db.refresh()
        }
        #expect(store.lastSaved == nil)
    }

    @Test("a count-field mismatch throws .implausibleFeed")
    func countMismatchThrowsImplausible() async throws {
        let store = MockThreatCacheStore()
        let feed = Fixture.liveFeedJSON(matching: [("CVE-2020-9054", "Zyxel", "desc")], countOverride: 50)
        let db = makeDatabase(cacheStore: store, fetchFeed: immediateFetcher {
            (feed, Fixture.httpResponse())
        })
        await #expect(throws: ThreatRefreshError.implausibleFeed) {
            _ = try await db.refresh()
        }
        #expect(store.lastSaved == nil)
    }

    // 7. A save failure surfaces .persistence and leaves lookups/status untouched
    @Test("a save failure throws .persistence and leaves prior state intact")
    func saveFailureThrowsPersistence() async throws {
        let store = MockThreatCacheStore()
        store.saveError = StubError()
        let feed = Fixture.liveFeedJSON(catalogVersion: "2026.03.01", matching: [
            ("CVE-2011-2523", "vsftpd - should not apply", "desc"),
        ])
        let db = makeDatabase(cacheStore: store, fetchFeed: immediateFetcher {
            (feed, Fixture.httpResponse())
        })
        await #expect(throws: ThreatRefreshError.persistence) {
            _ = try await db.refresh()
        }
        let results = await db.lookup(manufacturer: nil, serviceType: "_ftp._tcp", port: nil)
        let untouched = results.first { $0.cveID == "CVE-2011-2523" }
        #expect(untouched?.source == .nist)
        #expect(untouched?.vulnerabilityName == "vsftpd 2.3.4 Backdoor")
    }

    // 8. Relaunch: a fresh instance reflects a previously-saved cache
    @Test("a fresh instance reflects a cache written by a prior instance")
    func relaunchReflectsPersistedCache() async throws {
        let fetchedAt = Date(timeIntervalSince1970: 1_800_000_000)
        let cache = KEVCacheFile(
            schemaVersion: KEVCacheFile.currentSchema,
            fetchedAt: fetchedAt,
            catalogVersion: "2026.03.01",
            catalogDateReleased: "2026-03-01T00:00:00.0000Z",
            entries: ["CVE-2011-2523": CISAKEVEntry(
                cveID: "CVE-2011-2523", vendorProject: "GNU", product: "vsftpd",
                vulnerabilityName: "vsftpd Backdoor (cached)", shortDescription: "desc", dateAdded: nil
            )]
        )
        let store = MockThreatCacheStore(initial: cache)
        let db = makeDatabase(cacheStore: store)

        let results = await db.lookup(manufacturer: nil, serviceType: "_ftp._tcp", port: nil)
        let promoted = results.first { $0.cveID == "CVE-2011-2523" }
        #expect(promoted?.source == .cisa)

        let status = await db.status()
        #expect(status.lastSuccessfulRefresh == fetchedAt)
    }

    // 9. A corrupt/mismatched-schema cache is ignored, not crashed on
    @Test("a cache with a future schema version is ignored, falling back to bundled data")
    func futureSchemaCacheIsIgnored() async {
        struct FutureCacheStore: ThreatCacheStoring {
            func load() throws -> KEVCacheFile? {
                // Simulate a schema this build doesn't understand by
                // decoding through the current shape but with a bumped
                // version number - ensureLoaded() should discard it.
                KEVCacheFile(
                    schemaVersion: KEVCacheFile.currentSchema + 1,
                    fetchedAt: Date(),
                    catalogVersion: "2099.01.01",
                    catalogDateReleased: nil,
                    entries: ["CVE-2011-2523": CISAKEVEntry(
                        cveID: "CVE-2011-2523", vendorProject: "x", product: "x",
                        vulnerabilityName: "should not apply", shortDescription: "x", dateAdded: nil
                    )]
                )
            }
            func save(_ file: KEVCacheFile) throws {}
        }
        let db = makeDatabase(cacheStore: FutureCacheStore())
        let results = await db.lookup(manufacturer: nil, serviceType: "_ftp._tcp", port: nil)
        let entry = results.first { $0.cveID == "CVE-2011-2523" }
        #expect(entry?.source == .nist)
        #expect(entry?.vulnerabilityName == "vsftpd 2.3.4 Backdoor")
    }

    // 10. Load order: lookup() as the very first call already reflects bundled + cache
    @Test("lookup as the first call already reflects bundled data")
    func firstCallReflectsBundledData() async {
        let db = makeDatabase()
        let results = await db.lookup(manufacturer: nil, serviceType: "_ftp._tcp", port: nil)
        #expect(results.contains { $0.cveID == "CVE-2020-9054" && $0.source == .cisa })
    }

    // 11. A second refresh while the first is suspended throws .alreadyRefreshing
    @Test("a concurrent second refresh throws .alreadyRefreshing")
    func concurrentRefreshThrowsAlreadyRefreshing() async throws {
        let gate = GatedFetcher()
        await gate.setResult(.success((Fixture.liveFeedJSON(matching: []), Fixture.httpResponse())))
        let store = MockThreatCacheStore()
        let db = makeDatabase(cacheStore: store, fetchFeed: { try await gate.fetch() })

        let first = Task { try await db.refresh() }
        // Give the first refresh a moment to set isFetching before the
        // second one starts.
        try await Task.sleep(nanoseconds: 20_000_000)

        await #expect(throws: ThreatRefreshError.alreadyRefreshing) {
            _ = try await db.refresh()
        }

        await gate.release()
        _ = try await first.value
    }

    // 12. FileThreatCacheStore round trip
    @Test("FileThreatCacheStore round trip; missing file gives nil")
    func fileStoreRoundTrip() throws {
        let tmpDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ThreatDatabaseTests-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmpDir) }
        let store = FileThreatCacheStore(fileURL: tmpDir.appendingPathComponent("kev_cache.json"))

        #expect(try store.load() == nil)

        let cache = KEVCacheFile(
            schemaVersion: KEVCacheFile.currentSchema,
            fetchedAt: Date(timeIntervalSince1970: 1_800_000_000),
            catalogVersion: "2026.03.01",
            catalogDateReleased: "2026-03-01T00:00:00.0000Z",
            entries: ["CVE-2011-2523": CISAKEVEntry(
                cveID: "CVE-2011-2523", vendorProject: "GNU", product: "vsftpd",
                vulnerabilityName: "vsftpd Backdoor", shortDescription: "desc", dateAdded: nil
            )]
        )
        try store.save(cache)
        let loaded = try store.load()
        #expect(loaded == cache)
    }
}

// Reads the real app-bundle resources, not the fixtures above - requires
// this test target to be hosted by the mDNSShark app target (TEST_HOST) so
// Bundle.main resolves to the app bundle rather than the test bundle.
@Suite("Bundled resources consistency")
struct BundledResourcesConsistencyTests {
    private func loadBundledCatalog() throws -> CISAKEVCatalog {
        let url = try #require(Bundle.main.url(forResource: "cisa_kev_snapshot", withExtension: "json"))
        return try JSONDecoder().decode(CISAKEVCatalog.self, from: Data(contentsOf: url))
    }

    private func loadBundledMap() throws -> NistCPEMap {
        let url = try #require(Bundle.main.url(forResource: "nist_cpe_map", withExtension: "json"))
        return try JSONDecoder().decode(NistCPEMap.self, from: Data(contentsOf: url))
    }

    // 19. Real-bundle consistency
    @Test("every bundled snapshot CVE is referenced by the map (catches orphans)")
    func noOrphanedSnapshotEntries() throws {
        let catalog = try loadBundledCatalog()
        let map = try loadBundledMap()
        for entry in catalog.vulnerabilities {
            #expect(map.referencedCVEs.contains(entry.cveID), "\(entry.cveID) is bundled but not referenced by nist_cpe_map.json")
        }
    }

    @Test("every referenced CVE has either a bundled KEV record or curated text")
    func everyReferencedCVEHasText() throws {
        let catalog = try loadBundledCatalog()
        let map = try loadBundledMap()
        let kevIDs = Set(catalog.vulnerabilities.map(\.cveID))
        for cve in map.referencedCVEs {
            let hasKEV = kevIDs.contains(cve)
            let hasCurated = map.cves?[cve] != nil
            #expect(hasKEV || hasCurated, "\(cve) has neither a bundled KEV entry nor curated text")
        }
    }

    @Test("bundled snapshot carries catalogVersion and snapshotDate")
    func snapshotHasMetadata() throws {
        let catalog = try loadBundledCatalog()
        #expect(catalog.catalogVersion != nil)
        #expect(catalog.snapshotDate != nil)
    }
}
