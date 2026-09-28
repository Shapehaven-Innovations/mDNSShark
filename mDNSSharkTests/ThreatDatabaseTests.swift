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

    // MARK: - Vendor advisory matching

    @Test("a manufacturer matching a KEV-covered vendor returns that vendor's KEV entries")
    func vendorAdvisoryMatchesKEVVendor() async {
        let db = makeDatabase()
        let matches = await db.vendorAdvisory(manufacturer: "ASUSTek COMPUTER INC.")
        #expect(matches.map(\.cveID) == ["CVE-2023-3333"])
        #expect(matches.first?.vendorDisplayName == "ASUS")
        #expect(matches.first?.source == .kev)
    }

    @Test("a manufacturer matching an NVD-only vendor (no KEV coverage yet) returns nothing in PR1")
    func vendorAdvisoryEmptyForNVDOnlyVendor() async {
        let db = makeDatabase()
        let matches = await db.vendorAdvisory(manufacturer: "Commscope")
        #expect(matches.isEmpty)
    }

    @Test("an unrelated manufacturer returns no vendor advisory")
    func vendorAdvisoryEmptyForUnknownManufacturer() async {
        let db = makeDatabase()
        let matches = await db.vendorAdvisory(manufacturer: "Apple Inc.")
        #expect(matches.isEmpty)
    }

    @Test("whole-token matching: a hyphenated OUI name still resolves via the hyphen-stripped token")
    func vendorAdvisoryMatchesHyphenatedOUIName() async {
        let db = makeDatabase()
        // "ASUS-TEK Computer Inc." strips to "ASUSTEK Computer Inc." -> token "asustek".
        let matches = await db.vendorAdvisory(manufacturer: "ASUS-TEK Computer Inc.")
        #expect(matches.map(\.cveID) == ["CVE-2023-3333"])
    }

    @Test("substring matching is rejected: a vendor name embedded in a longer word does not match")
    func vendorAdvisoryRejectsSubstringMatch() async {
        let db = makeDatabase()
        // "Harris Corporation" contains "arris" as a substring of "Harris" but
        // is not a whole-token match for the "arris" alias.
        let matches = await db.vendorAdvisory(manufacturer: "Harris Corporation")
        #expect(matches.isEmpty)
    }

    // 2/3/4. Refresh promotes/adds, keeps fallback, overlays text - all via
    // vendorAdvisory() now, the only surviving per-CVE lookup path.
    @Test("a successful refresh adds a new vendor-claimed CVE the bundle didn't have")
    func refreshAddsNewVendorClaimedCVE() async throws {
        let store = MockThreatCacheStore()
        let feed = Fixture.liveFeedJSON(catalogVersion: "2026.03.01", matching: [
            ("CVE-2020-9054", "Zyxel NAS OS Command Injection (updated)", "updated desc"),
            ("CVE-2026-1111", "Zyxel New Router RCE", "new desc"),
        ])
        let db = makeDatabase(cacheStore: store, fetchFeed: immediateFetcher {
            (feed, Fixture.httpResponse())
        })
        _ = try await db.refresh()
        let matches = await db.vendorAdvisory(manufacturer: "Zyxel")
        #expect(Set(matches.map(\.cveID)) == ["CVE-2020-9054", "CVE-2026-1111"])
        let updated = matches.first { $0.cveID == "CVE-2020-9054" }
        #expect(updated?.title == "Zyxel NAS OS Command Injection (updated)")
    }

    @Test("a bundled KEV CVE absent from a newer feed keeps its bundled CISA attribution")
    func refreshKeepsBundledWhenAbsentFromFeed() async throws {
        let store = MockThreatCacheStore()
        // Feed doesn't include CVE-2020-9054 at all, only an unrelated
        // Zyxel-claimed CVE.
        let feed = Fixture.liveFeedJSON(catalogVersion: "2026.03.01", matching: [
            ("CVE-2026-2222", "Zyxel Other Bug", "desc"),
        ])
        let db = makeDatabase(cacheStore: store, fetchFeed: immediateFetcher {
            (feed, Fixture.httpResponse())
        })
        _ = try await db.refresh()
        let matches = await db.vendorAdvisory(manufacturer: "Zyxel")
        let stillThere = matches.first { $0.cveID == "CVE-2020-9054" }
        #expect(stillThere?.source == .kev)
        #expect(stillThere?.title == "Zyxel NAS OS Command Injection")
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
        let matches = await db.vendorAdvisory(manufacturer: "Zyxel")
        let updated = matches.first { $0.cveID == "CVE-2020-9054" }
        #expect(updated?.title == "Zyxel NAS - renamed")
    }

    // 5. Only vendor-claimed CVEs are saved
    @Test("refresh only persists CVEs a vendorAdvisories entry actually claims")
    func refreshPersistsOnlyVendorClaimedSubset() async throws {
        let store = MockThreatCacheStore()
        let feed = Fixture.liveFeedJSON(catalogVersion: "2026.03.01", matching: [
            ("CVE-2020-9054", "Zyxel", "desc"),
            ("CVE-2023-39238", "ASUS", "desc"),
            ("CVE-2026-3333", "Unclaimed", "desc"),
        ], vendorProjects: ["Zyxel", "ASUS", "SomeVendorNobodyClaims"])
        let db = makeDatabase(cacheStore: store, fetchFeed: immediateFetcher {
            (feed, Fixture.httpResponse())
        })
        _ = try await db.refresh()
        let savedKeys = Set((store.lastSaved?.entries ?? [:]).keys)
        #expect(savedKeys == ["CVE-2020-9054", "CVE-2023-39238"])
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
            ("CVE-2020-9054", "Zyxel - should not apply", "desc"),
        ])
        let db = makeDatabase(cacheStore: store, fetchFeed: immediateFetcher {
            (feed, Fixture.httpResponse())
        })
        await #expect(throws: ThreatRefreshError.persistence) {
            _ = try await db.refresh()
        }
        let matches = await db.vendorAdvisory(manufacturer: "Zyxel")
        let untouched = matches.first { $0.cveID == "CVE-2020-9054" }
        #expect(untouched?.source == .kev)
        #expect(untouched?.title == "Zyxel NAS OS Command Injection")
    }

    // 8. Relaunch: a fresh instance reflects a previously-saved cache
    @Test("a fresh instance reflects a cache written by a prior instance")
    func relaunchReflectsPersistedCache() async throws {
        let fetchedAt = Date(timeIntervalSince1970: 1_800_000_000)
        let cache = KEVCacheFile(
            schemaVersion: KEVCacheFile.currentSchema,
            kevFetchedAt: fetchedAt,
            catalogVersion: "2026.03.01",
            catalogDateReleased: "2026-03-01T00:00:00.0000Z",
            entries: ["CVE-2020-9054": CISAKEVEntry(
                cveID: "CVE-2020-9054", vendorProject: "Zyxel", product: "NAS",
                vulnerabilityName: "Zyxel NAS OS Command Injection (cached)", shortDescription: "desc", dateAdded: nil
            )],
            nvdVendors: [:],
            nvdVendorLastSeen: [:],
            nvdLastCheckedAt: nil
        )
        let store = MockThreatCacheStore(initial: cache)
        let db = makeDatabase(cacheStore: store)

        let matches = await db.vendorAdvisory(manufacturer: "Zyxel")
        let promoted = matches.first { $0.cveID == "CVE-2020-9054" }
        #expect(promoted?.title == "Zyxel NAS OS Command Injection (cached)")

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
                    kevFetchedAt: Date(),
                    catalogVersion: "2099.01.01",
                    catalogDateReleased: nil,
                    entries: ["CVE-2020-9054": CISAKEVEntry(
                        cveID: "CVE-2020-9054", vendorProject: "Zyxel", product: "x",
                        vulnerabilityName: "should not apply", shortDescription: "x", dateAdded: nil
                    )],
                    nvdVendors: [:],
                    nvdVendorLastSeen: [:],
                    nvdLastCheckedAt: nil
                )
            }
            func save(_ file: KEVCacheFile) throws {}
        }
        let db = makeDatabase(cacheStore: FutureCacheStore())
        let matches = await db.vendorAdvisory(manufacturer: "Zyxel")
        let entry = matches.first { $0.cveID == "CVE-2020-9054" }
        #expect(entry?.title == "Zyxel NAS OS Command Injection")
    }

    // 10. Load order: vendorAdvisory() as the very first call already reflects bundled + cache
    @Test("vendorAdvisory as the first call already reflects bundled data")
    func firstCallReflectsBundledData() async {
        let db = makeDatabase()
        let matches = await db.vendorAdvisory(manufacturer: "Zyxel")
        #expect(matches.contains { $0.cveID == "CVE-2020-9054" && $0.source == .kev })
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

    // 12a. A cache file written before nvdVendorLastSeen/nvdLastCheckedAt
    // existed (PR C) still decodes cleanly, with both new fields nil.
    @Test("a pre-PR-C cache file missing the new optional fields still decodes")
    func preExistingCacheFileDecodesWithNewFieldsNil() throws {
        let json = """
        {
          "schemaVersion": 2,
          "kevFetchedAt": "2026-03-01T00:00:00Z",
          "catalogVersion": "2026.03.01",
          "catalogDateReleased": "2026-03-01T00:00:00.0000Z",
          "entries": {
            "CVE-2020-9054": {
              "cveID": "CVE-2020-9054", "vendorProject": "Zyxel", "product": "NAS",
              "vulnerabilityName": "Zyxel NAS OS Command Injection", "shortDescription": "desc"
            }
          },
          "nvdVendors": {}
        }
        """.data(using: .utf8)!
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(KEVCacheFile.self, from: json)
        #expect(decoded.nvdVendorLastSeen == nil)
        #expect(decoded.nvdLastCheckedAt == nil)
        #expect(decoded.schemaVersion == 2)
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
            kevFetchedAt: Date(timeIntervalSince1970: 1_800_000_000),
            catalogVersion: "2026.03.01",
            catalogDateReleased: "2026-03-01T00:00:00.0000Z",
            entries: ["CVE-2011-2523": CISAKEVEntry(
                cveID: "CVE-2011-2523", vendorProject: "GNU", product: "vsftpd",
                vulnerabilityName: "vsftpd Backdoor", shortDescription: "desc", dateAdded: nil
            )],
            nvdVendors: [:],
            nvdVendorLastSeen: [:],
            nvdLastCheckedAt: nil
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
    @Test("every bundled snapshot CVE is vendor-claimed (catches orphans)")
    func noOrphanedSnapshotEntries() throws {
        let catalog = try loadBundledCatalog()
        let map = try loadBundledMap()
        let allowedProjects = Set(
            map.vendorAdvisories.values.flatMap { $0.kevVendorProjects.map { $0.lowercased() } }
        )
        for entry in catalog.vulnerabilities {
            let isVendorClaimed = allowedProjects.contains(entry.vendorProject.lowercased())
            #expect(isVendorClaimed, "\(entry.cveID) (\(entry.vendorProject)) is bundled but not claimed by any vendorAdvisories entry")
        }
    }

    @Test("every KEV-covered vendorAdvisories entry has at least one bundled snapshot entry")
    func everyKEVVendorHasABundledEntry() throws {
        let catalog = try loadBundledCatalog()
        let map = try loadBundledMap()
        let bundledProjects = Set(catalog.vulnerabilities.map { $0.vendorProject.lowercased() })
        for (key, config) in map.vendorAdvisories where !config.kevVendorProjects.isEmpty {
            let claims = Set(config.kevVendorProjects.map { $0.lowercased() })
            #expect(!claims.isDisjoint(with: bundledProjects), "vendor \"\(key)\" claims KEV coverage but no bundled snapshot entry has a matching vendorProject")
        }
    }

    @Test("bundled snapshot carries catalogVersion and snapshotDate")
    func snapshotHasMetadata() throws {
        let catalog = try loadBundledCatalog()
        #expect(catalog.catalogVersion != nil)
        #expect(catalog.snapshotDate != nil)
    }
}
