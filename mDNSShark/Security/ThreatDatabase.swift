// mDNSShark/Security/ThreatDatabase.swift
import Foundation
import os

struct ThreatEntry {
    enum ThreatSource { case cisa, nist }
    let cveID: String
    let vulnerabilityName: String
    let shortDescription: String
    let source: ThreatSource
}

typealias KEVFeedFetcher = @Sendable () async throws -> (Data, URLResponse)

enum ThreatRefreshError: Error, Equatable, Sendable {
    case alreadyRefreshing
    case cancelled
    case network(URLError.Code)
    case badStatus(Int)
    case undecodable
    case implausibleFeed
    case persistence
}

/// A snapshot of what mDNSShark currently knows about threat data
/// freshness. `bundledSnapshotDate`/`bundledCatalogVersion` describe the
/// data shipped with this app build; `lastSuccessfulRefresh`/
/// `refreshedCatalogVersion` describe the last successful manual refresh,
/// if any. `checkedCVECount` is the fixed number of CVEs this app version's
/// lookup rules can ever match — refreshing changes their attribution/text,
/// never which ones get checked (that only changes with an app update).
struct ThreatDataStatus: Equatable, Sendable {
    let bundledSnapshotDate: Date?
    let bundledCatalogVersion: String?
    let lastSuccessfulRefresh: Date?
    let refreshedCatalogVersion: String?
    let checkedCVECount: Int

    static let staleThreshold: TimeInterval = 30 * 24 * 60 * 60

    /// Pure, testable summary text for the Security tab's status line.
    func summary(now: Date = Date()) -> (text: String, isStale: Bool) {
        if let refreshed = lastSuccessfulRefresh {
            let age = now.timeIntervalSince(refreshed)
            let stale = age > Self.staleThreshold
            var text = "CISA exploit data: refreshed \(refreshed.formatted(date: .abbreviated, time: .omitted))."
            if stale { text += " Over 30 days old." }
            return (text, stale)
        }
        if let bundled = bundledSnapshotDate {
            let age = now.timeIntervalSince(bundled)
            let stale = age > Self.staleThreshold
            var text = "CISA exploit data: bundled with this app (\(bundled.formatted(date: .abbreviated, time: .omitted)))."
            if stale { text += " Over 30 days old." }
            return (text, stale)
        }
        return ("CISA exploit data: bundled with this app.", false)
    }
}

actor ThreatDatabase {
    private let bundledKEVData: Data?
    private let nistMapData: Data?
    private let cacheStore: ThreatCacheStoring
    private let fetchFeed: KEVFeedFetcher
    private let now: @Sendable () -> Date
    private let logger = Logger(subsystem: "com.mDNSShark", category: "ThreatDatabase")

    private var isLoaded = false
    private var isFetching = false

    private var bundledKEV: [String: CISAKEVEntry] = [:]
    private var bundledCatalogVersion: String?
    private var bundledSnapshotDate: Date?
    private var nistMap = NistCPEMap(serviceTypes: [:], manufacturers: [:], cves: nil)
    private var cache: KEVCacheFile?
    /// Bundled KEV entries overlaid by the cache, when the cache's own
    /// `catalogVersion` is at least as new as the bundled snapshot's. A
    /// cache written by an older app build stays inert here rather than
    /// clobbering a newer bundled snapshot after an app update (see
    /// `isCacheEligibleForOverlay`).
    private var kev: [String: CISAKEVEntry] = [:]

    init(
        bundledKEVData: Data?,
        nistMapData: Data?,
        cacheStore: ThreatCacheStoring,
        fetchFeed: @escaping KEVFeedFetcher,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.bundledKEVData = bundledKEVData
        self.nistMapData = nistMapData
        self.cacheStore = cacheStore
        self.fetchFeed = fetchFeed
        self.now = now
    }

    static func live() -> ThreatDatabase {
        let kevURL = URL(string: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")!
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.timeoutIntervalForResource = 60
        sessionConfig.waitsForConnectivity = false
        let session = URLSession(configuration: sessionConfig)

        let bundledKEVData = Bundle.main.url(forResource: "cisa_kev_snapshot", withExtension: "json")
            .flatMap { try? Data(contentsOf: $0) }
        let nistMapData = Bundle.main.url(forResource: "nist_cpe_map", withExtension: "json")
            .flatMap { try? Data(contentsOf: $0) }

        return ThreatDatabase(
            bundledKEVData: bundledKEVData,
            nistMapData: nistMapData,
            cacheStore: FileThreatCacheStore.appDefault(),
            fetchFeed: {
                let request = URLRequest(url: kevURL, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 20)
                return try await session.data(for: request)
            }
        )
    }

    // MARK: - Loading

    /// Synchronous and non-suspending by construction (no `await` in its
    /// body), so it runs atomically under actor reentrancy: no caller can
    /// observe a half-loaded state, and a concurrent `refresh()` can never
    /// interleave with the initial load. Guarded by `isLoaded` so the
    /// (cheap, few-KB) bundled decode only happens once.
    private func ensureLoaded() {
        guard !isLoaded else { return }
        isLoaded = true

        if let data = bundledKEVData,
           let catalog = try? JSONDecoder().decode(CISAKEVCatalog.self, from: data) {
            bundledKEV = Dictionary(uniqueKeysWithValues: catalog.vulnerabilities.map { ($0.cveID, $0) })
            bundledCatalogVersion = catalog.catalogVersion
            bundledSnapshotDate = catalog.snapshotDate.flatMap(Self.parseSnapshotDate)
            logger.info("Loaded \(catalog.vulnerabilities.count) bundled CISA KEV entries")
        }

        if let data = nistMapData,
           let map = try? JSONDecoder().decode(NistCPEMap.self, from: data) {
            nistMap = map
            logger.info("Loaded NIST CPE map")
        }

        if let loaded = try? cacheStore.load(), loaded.schemaVersion == KEVCacheFile.currentSchema {
            cache = loaded
        }

        recomputeMergedKEV()
    }

    private func recomputeMergedKEV() {
        guard let cache, isCacheEligibleForOverlay(cache) else {
            kev = bundledKEV
            return
        }
        kev = bundledKEV.merging(cache.entries) { _, cached in cached }
    }

    /// A cache only overlays the bundled snapshot when it is at least as
    /// new, by CISA's own `catalogVersion` (format `YYYY.MM.DD`, so a plain
    /// string compare is a valid date compare). This is what stops a stale
    /// cache from an old refresh silently outranking a newer bundled
    /// snapshot shipped in a later app update; `cache.fetchedAt` is still
    /// used for the status line's "last refreshed" date regardless, since
    /// that's a fact about when the user last refreshed, not about which
    /// data wins the merge.
    private func isCacheEligibleForOverlay(_ cache: KEVCacheFile) -> Bool {
        guard let cacheVersion = cache.catalogVersion else { return false }
        guard let bundledVersion = bundledCatalogVersion else { return true }
        return cacheVersion >= bundledVersion
    }

    private static func parseSnapshotDate(_ string: String) -> Date? {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.timeZone = TimeZone(identifier: "UTC")
        return formatter.date(from: string)
    }

    // MARK: - Status

    func status() -> ThreatDataStatus {
        ensureLoaded()
        return ThreatDataStatus(
            bundledSnapshotDate: bundledSnapshotDate,
            bundledCatalogVersion: bundledCatalogVersion,
            lastSuccessfulRefresh: cache?.fetchedAt,
            refreshedCatalogVersion: cache?.catalogVersion,
            checkedCVECount: nistMap.referencedCVEs.count
        )
    }

    // MARK: - Refresh

    /// Fetches, validates, filters, and saves before touching any
    /// in-memory state, so every failure path leaves both memory and disk
    /// exactly as they were and in-memory state always matches what would
    /// survive a relaunch.
    func refresh() async throws -> ThreatDataStatus {
        ensureLoaded()
        guard !isFetching else { throw ThreatRefreshError.alreadyRefreshing }
        isFetching = true
        defer { isFetching = false }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await fetchFeed()
        } catch is CancellationError {
            throw ThreatRefreshError.cancelled
        } catch let urlError as URLError where urlError.code == .cancelled {
            throw ThreatRefreshError.cancelled
        } catch let urlError as URLError {
            throw ThreatRefreshError.network(urlError.code)
        } catch {
            throw ThreatRefreshError.network(.unknown)
        }

        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            let code = (response as? HTTPURLResponse)?.statusCode ?? -1
            throw ThreatRefreshError.badStatus(code)
        }

        guard let catalog = try? JSONDecoder().decode(CISAKEVCatalog.self, from: data) else {
            throw ThreatRefreshError.undecodable
        }

        // Guards against a captive-portal HTML page (would already have
        // failed decode above) and a truncated/short response that still
        // happens to decode, e.g. a proxy returning `{"vulnerabilities":[]}`.
        guard catalog.vulnerabilities.count >= 1000,
              catalog.count == nil || catalog.count == catalog.vulnerabilities.count else {
            throw ThreatRefreshError.implausibleFeed
        }

        do {
            try Task.checkCancellation()
        } catch {
            throw ThreatRefreshError.cancelled
        }

        let referenced = nistMap.referencedCVEs
        let filtered = catalog.vulnerabilities.filter { referenced.contains($0.cveID) }
        let entries = Dictionary(uniqueKeysWithValues: filtered.map { ($0.cveID, $0) })

        let newCache = KEVCacheFile(
            schemaVersion: KEVCacheFile.currentSchema,
            fetchedAt: now(),
            catalogVersion: catalog.catalogVersion,
            catalogDateReleased: catalog.dateReleased,
            entries: entries
        )

        do {
            try cacheStore.save(newCache)
        } catch {
            throw ThreatRefreshError.persistence
        }

        cache = newCache
        recomputeMergedKEV()
        logger.info("Refreshed threat data: \(entries.count) referenced CVEs cached")
        return status()
    }

    // MARK: - Lookup

    func lookup(manufacturer: String?, serviceType: String?, port: Int?) async -> [ThreatEntry] {
        ensureLoaded()
        var results: [ThreatEntry] = []

        if let st = serviceType, let entry = nistMap.serviceTypes[st], !entry.cves.isEmpty {
            for cve in entry.cves {
                results.append(threatEntry(for: cve, fallbackTitle: "\(st) Known Vulnerability", fallbackDescription: entry.description))
            }
        }

        if let mfr = manufacturer {
            for (key, entry) in nistMap.manufacturers where mfr.lowercased().contains(key.lowercased()) {
                for cve in entry.cves {
                    results.append(threatEntry(for: cve, fallbackTitle: "\(key) Known Vulnerability", fallbackDescription: entry.description))
                }
                break
            }
        }
        return results
    }

    /// Lookup precedence: a live/cached KEV match (real CISA attribution)
    /// beats curated NVD-sourced text, which beats the generic fallback.
    /// The three sources are disjoint by construction (curated `cves`
    /// entries only exist for CVEs this app's snapshot script found were
    /// NOT in the live KEV feed), so there's no ambiguity about which wins.
    private func threatEntry(for cve: String, fallbackTitle: String, fallbackDescription: String) -> ThreatEntry {
        if let kevEntry = kev[cve] {
            return ThreatEntry(cveID: kevEntry.cveID, vulnerabilityName: kevEntry.vulnerabilityName,
                                shortDescription: kevEntry.shortDescription, source: .cisa)
        }
        if let curated = nistMap.cves?[cve] {
            return ThreatEntry(cveID: cve, vulnerabilityName: curated.title,
                                shortDescription: curated.description, source: .nist)
        }
        return ThreatEntry(cveID: cve, vulnerabilityName: fallbackTitle,
                            shortDescription: fallbackDescription, source: .nist)
    }
}

// MARK: - Decodable models

struct CISAKEVCatalog: Decodable {
    let catalogVersion: String?
    let dateReleased: String?
    let snapshotDate: String?
    let count: Int?
    let vulnerabilities: [CISAKEVEntry]
}

struct CISAKEVEntry: Codable, Equatable, Sendable {
    let cveID: String
    let vendorProject: String
    let product: String
    let vulnerabilityName: String
    let shortDescription: String
    let dateAdded: String?
}

struct NistCPEMap: Decodable {
    let serviceTypes: [String: NistServiceEntry]
    let manufacturers: [String: NistManufacturerEntry]
    let cves: [String: NistCVEText]?

    var referencedCVEs: Set<String> {
        var set = Set<String>()
        for entry in serviceTypes.values { set.formUnion(entry.cves) }
        for entry in manufacturers.values { set.formUnion(entry.cves) }
        return set
    }
}
struct NistServiceEntry: Decodable { let cves: [String]; let description: String }
struct NistManufacturerEntry: Decodable { let cves: [String]; let description: String }
struct NistCVEText: Decodable { let title: String; let description: String }
