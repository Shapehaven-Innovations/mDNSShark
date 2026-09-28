// mDNSShark/Security/ThreatDatabase.swift
import Foundation
import os

/// A grouped vendor-level match: this device's manufacturer resolved to a
/// vendor with a live KEV and/or NVD match. `cvssBaseSeverity`/`cvssBaseScore`
/// are always nil for `.kev` entries (KEV records don't carry CVSS scores)
/// and always present for `.nvd` entries that made it this far (anything
/// without an extractable CRITICAL/HIGH/MEDIUM severity is filtered out
/// before it's ever cached - see `ThreatDatabase.appSeverity`).
struct VendorFinding: Sendable {
    enum Source: String, Sendable { case kev, nvd }
    let cveID: String
    let vendorKey: String
    let vendorDisplayName: String
    let title: String
    let description: String
    let source: Source
    let cvssBaseSeverity: String?
    let cvssBaseScore: Double?
    let dateAdded: String?
}

typealias KEVFeedFetcher = @Sendable () async throws -> (Data, URLResponse)
/// Fetches one NVD `keywordSearch` query for the given alias string.
typealias NVDFeedFetcher = @Sendable (String) async throws -> (Data, URLResponse)

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
/// `refreshedCatalogVersion` describe the last successful manual KEV
/// refresh, if any. `vendorCount` is the number of vendors with live KEV
/// coverage; `nvdVendorCount` is the number with live NVD coverage (PR2) -
/// both are checked live against refreshed data and can gain/lose findings
/// without an app update. `nvdLastSuccessfulRefresh` is the most recent
/// successful NVD fetch across all vendors; NVD refreshes per-vendor
/// independently of KEV and of each other, so this is a summary, not a
/// guarantee every vendor is that fresh.
struct ThreatDataStatus: Equatable, Sendable {
    let bundledSnapshotDate: Date?
    let bundledCatalogVersion: String?
    let lastSuccessfulRefresh: Date?
    let refreshedCatalogVersion: String?
    let vendorCount: Int
    var nvdLastSuccessfulRefresh: Date? = nil
    var nvdVendorCount: Int = 0
    /// When the NVD phase last completed, whether or not it found any
    /// vendor worth querying. Distinct from `nvdLastSuccessfulRefresh`
    /// (which only advances when a vendor was actually fetched): most LANs
    /// have none of the NVD-covered vendors present, so without this field
    /// the status line would say "not yet refreshed" forever even after a
    /// refresh that correctly found nothing to do.
    var nvdLastCheckedAt: Date? = nil

    static let staleThreshold: TimeInterval = 30 * 24 * 60 * 60

    /// Pure, testable summary text for the Security tab's status line.
    /// Reports KEV and NVD state as two honest, independent clauses rather
    /// than one combined status, since a refresh can succeed for one source
    /// and fail (or simply not have run yet) for the other. NVD has three
    /// distinct states, not two: never checked, checked but nothing to
    /// query (no covered vendor on this LAN), or refreshed with data.
    func summary(now: Date = Date()) -> (text: String, isStale: Bool) {
        var kevStale = false
        var kevText: String
        if let refreshed = lastSuccessfulRefresh {
            let age = now.timeIntervalSince(refreshed)
            kevStale = age > Self.staleThreshold
            kevText = "CISA exploit data: refreshed \(refreshed.formatted(date: .abbreviated, time: .omitted))."
            if kevStale { kevText += " Over 30 days old." }
        } else if let bundled = bundledSnapshotDate {
            let age = now.timeIntervalSince(bundled)
            kevStale = age > Self.staleThreshold
            kevText = "CISA exploit data: bundled with this app (\(bundled.formatted(date: .abbreviated, time: .omitted)))."
            if kevStale { kevText += " Over 30 days old." }
        } else {
            kevText = "CISA exploit data: bundled with this app."
        }

        guard nvdVendorCount > 0 else {
            return (kevText, kevStale)
        }

        var nvdStale = false
        var nvdText: String
        if let refreshed = nvdLastSuccessfulRefresh {
            let age = now.timeIntervalSince(refreshed)
            nvdStale = age > Self.staleThreshold
            nvdText = "NVD: refreshed \(refreshed.formatted(date: .abbreviated, time: .omitted))."
            if nvdStale { nvdText += " Over 30 days old." }
        } else if let checked = nvdLastCheckedAt {
            nvdText = "NVD: checked \(checked.formatted(date: .abbreviated, time: .omitted)), no covered vendors on this network."
        } else {
            nvdText = "NVD: not yet refreshed."
        }

        return ("\(kevText) \(nvdText)", kevStale || nvdStale)
    }
}

actor ThreatDatabase {
    private let bundledKEVData: Data?
    private let nistMapData: Data?
    private let cacheStore: ThreatCacheStoring
    private let fetchFeed: KEVFeedFetcher
    private let fetchNVDFeed: NVDFeedFetcher
    /// Injectable so tests can verify the rate-limit spacing logic (called
    /// once between every two sequential NVD requests) without a real
    /// multi-second wait per test run.
    private let sleepNanoseconds: @Sendable (UInt64) async throws -> Void
    private let now: @Sendable () -> Date
    private let logger = Logger(subsystem: "com.mDNSShark", category: "ThreatDatabase")

    /// Spacing between sequential NVD requests. NVD's unauthenticated limit
    /// is 5 requests/30s; ~6.5s keeps a comfortable margin without a
    /// registered API key (skipped deliberately - a config secret for a
    /// free-tier app isn't worth the setup burden for what's currently a
    /// once-per-manual-refresh, ~10-request sequence).
    private let nvdRequestSpacing: UInt64 = 6_500_000_000

    private var isLoaded = false
    private var isFetching = false
    private var isFetchingNVD = false

    private var bundledKEV: [String: CISAKEVEntry] = [:]
    private var bundledCatalogVersion: String?
    private var bundledSnapshotDate: Date?
    private var nistMap = NistCPEMap(vendorAdvisories: [:])
    private var cache: KEVCacheFile?
    /// Bundled KEV entries overlaid by the cache, when the cache's own
    /// `catalogVersion` is at least as new as the bundled snapshot's. A
    /// cache written by an older app build stays inert here rather than
    /// clobbering a newer bundled snapshot after an app update (see
    /// `isCacheEligibleForOverlay`). This dictionary backs both the
    /// the vendor-level `vendorAdvisory()`.
    private var kev: [String: CISAKEVEntry] = [:]
    /// Per-vendor NVD data, loaded from the cache and updated in place as
    /// each vendor's fetch succeeds. No bundled counterpart (NVD is never
    /// shipped in the app bundle) and no version-gated overlay - a vendor's
    /// entry here is simply whatever its last successful fetch produced.
    private var nvdByVendor: [String: NVDVendorCache] = [:]

    init(
        bundledKEVData: Data?,
        nistMapData: Data?,
        cacheStore: ThreatCacheStoring,
        fetchFeed: @escaping KEVFeedFetcher,
        fetchNVDFeed: @escaping NVDFeedFetcher = { _ in throw ThreatRefreshError.network(.unknown) },
        sleepNanoseconds: @escaping @Sendable (UInt64) async throws -> Void = { try await Task.sleep(nanoseconds: $0) },
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.bundledKEVData = bundledKEVData
        self.nistMapData = nistMapData
        self.cacheStore = cacheStore
        self.fetchFeed = fetchFeed
        self.fetchNVDFeed = fetchNVDFeed
        self.sleepNanoseconds = sleepNanoseconds
        self.now = now
    }

    static func live() -> ThreatDatabase {
        let kevURL = URL(string: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")!
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.timeoutIntervalForResource = 60
        sessionConfig.waitsForConnectivity = false
        let session = URLSession(configuration: sessionConfig)

        // NVD responds in well under a second in practice, but 45s of
        // headroom costs nothing and covers a slow/loaded moment - 20s like
        // the KEV request would be tight for an unmeasured external API.
        let nvdSessionConfig = URLSessionConfiguration.ephemeral
        nvdSessionConfig.timeoutIntervalForResource = 45
        nvdSessionConfig.waitsForConnectivity = false
        let nvdSession = URLSession(configuration: nvdSessionConfig)

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
            },
            fetchNVDFeed: { alias in
                var components = URLComponents(string: "https://services.nvd.nist.gov/rest/json/cves/2.0")!
                components.queryItems = [
                    URLQueryItem(name: "keywordSearch", value: alias),
                    URLQueryItem(name: "resultsPerPage", value: "2000")
                ]
                let request = URLRequest(url: components.url!, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 45)
                return try await nvdSession.data(for: request)
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
            nvdByVendor = loaded.nvdVendors
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
    /// snapshot shipped in a later app update; `cache.kevFetchedAt` is still
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
            lastSuccessfulRefresh: cache?.kevFetchedAt,
            refreshedCatalogVersion: cache?.catalogVersion,
            vendorCount: nistMap.vendorAdvisories.values.filter { !$0.kevVendorProjects.isEmpty }.count,
            nvdLastSuccessfulRefresh: nvdByVendor.values.map(\.fetchedAt).filter { $0 != .distantPast }.max(),
            nvdVendorCount: nistMap.vendorAdvisories.values.filter { !$0.nvdAliases.isEmpty }.count,
            nvdLastCheckedAt: cache?.nvdLastCheckedAt
        )
    }

    // MARK: - KEV Refresh

    /// Fetches, validates, filters, and saves before touching any
    /// in-memory state, so every failure path leaves both memory and disk
    /// exactly as they were and in-memory state always matches what would
    /// survive a relaunch. Only touches KEV data - any previously-fetched
    /// NVD data in the cache is carried through unchanged.
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

        // Cache only entries a vendor advisory could match by exact
        // `vendorProject` - the merge-not-replace/catalog-version-gate logic
        // below is unaffected by what's in this filter.
        let allowedProjects = Set(
            nistMap.vendorAdvisories.values.flatMap { $0.kevVendorProjects.map { $0.lowercased() } }
        )
        let filtered = catalog.vulnerabilities.filter {
            allowedProjects.contains($0.vendorProject.lowercased())
        }
        let entries = Dictionary(uniqueKeysWithValues: filtered.map { ($0.cveID, $0) })

        let newCache = buildCacheFile(
            kevFetchedAt: now(),
            catalogVersion: catalog.catalogVersion,
            catalogDateReleased: catalog.dateReleased,
            entries: entries,
            nvdVendors: cache?.nvdVendors ?? [:],
            nvdVendorLastSeen: cache?.nvdVendorLastSeen ?? [:],
            nvdLastCheckedAt: cache?.nvdLastCheckedAt
        )

        do {
            try cacheStore.save(newCache)
        } catch {
            throw ThreatRefreshError.persistence
        }

        cache = newCache
        recomputeMergedKEV()
        logger.info("Refreshed KEV threat data: \(entries.count) CVEs cached")
        return status()
    }

    // MARK: - NVD Refresh

    /// Fetches NVD data only for vendors worth querying right now: present
    /// among `priorityManufacturers` (the current scan), or seen within the
    /// last `ThreatDataStatus.staleThreshold` (30 days, so a temporarily
    /// offline device doesn't instantly drop out of scope), AND not already
    /// fetched within the last 24h (checked before any request goes out, so
    /// a skipped vendor costs no rate-limit spacing). Left unfiltered, this
    /// method queried all ~9 NVD-covered vendors every refresh regardless of
    /// LAN presence - about 75s of pure rate-limit spacing for a typical
    /// home with 0-1 relevant vendors present.
    ///
    /// One HTTP request per vendor/alias pair, spaced to respect NVD's
    /// unauthenticated rate limit. Present-on-this-scan vendors are queried
    /// first, so a cancelled or partially-completed refresh still surfaces
    /// useful data for devices actually on the user's network. Commits and
    /// persists each vendor's result as soon as that vendor's aliases
    /// finish, not all-or-nothing at the end - a failure or timeout on one
    /// vendor never rolls back an earlier vendor's fresh data. A per-alias
    /// network failure is logged and skipped rather than aborting the whole
    /// vendor, but a vendor with more than one alias (Arris, Technicolor,
    /// DZS) that only gets SOME of its aliases back is deliberately not
    /// treated as fully fresh: its `fetchedAt` isn't advanced, so it's
    /// retried in full next refresh regardless of the 24h TTL, and whatever
    /// this run did collect is merged into (never replaces) its previously
    /// cached entries so a transient failure can't lose data an earlier,
    /// fully-successful fetch already found. Only cancellation (from
    /// `cancelThreatDataRefresh()`, e.g. LAN capture starting mid-refresh)
    /// propagates out of this method; every other failure is contained to
    /// the vendor/alias it happened on.
    func refreshNVDVendorData(priorityManufacturers: [String]) async throws {
        ensureLoaded()
        guard !isFetchingNVD else { throw ThreatRefreshError.alreadyRefreshing }
        isFetchingNVD = true
        defer { isFetchingNVD = false }

        let eligible = nistMap.vendorAdvisories.filter { !$0.value.nvdAliases.isEmpty }
        guard !eligible.isEmpty else { return }

        let nowDate = now()
        // Order-preserving: `orderVendorKeys` below needs the original
        // first-seen order to put priority vendors first correctly -
        // `presentKeys` (a Set, used for membership/lastSeen bookkeeping)
        // would silently lose that order if used for the priority list
        // directly.
        let priorityKeysOrdered = priorityManufacturers.compactMap { resolveVendor(forManufacturer: $0)?.key }
        let presentKeys = Set(priorityKeysOrdered).intersection(eligible.keys)

        var lastSeen = cache?.nvdVendorLastSeen ?? [:]
        for key in presentKeys { lastSeen[key] = nowDate }

        let recentlySeenKeys = Set(eligible.keys.filter { key in
            guard let seen = lastSeen[key] else { return false }
            return nowDate.timeIntervalSince(seen) <= ThreatDataStatus.staleThreshold
        })
        let candidateKeys = presentKeys.union(recentlySeenKeys)

        guard !candidateKeys.isEmpty else {
            persistNVDCheckpoint(lastSeen: lastSeen, checkedAt: nowDate)
            return
        }

        let vendorTTL: TimeInterval = 24 * 60 * 60
        let toQuery = candidateKeys.filter { key in
            guard let existing = nvdByVendor[key] else { return true }
            return nowDate.timeIntervalSince(existing.fetchedAt) >= vendorTTL
        }

        guard !toQuery.isEmpty else {
            persistNVDCheckpoint(lastSeen: lastSeen, checkedAt: nowDate)
            return
        }

        let orderedKeys = orderVendorKeys(allKeys: Array(toQuery), priority: priorityKeysOrdered)

        var isFirstRequest = true
        for key in orderedKeys {
            guard let config = eligible[key] else { continue }
            var collected: [String: NVDCachedEntry] = [:]
            var allAliasesSucceeded = true

            for alias in config.nvdAliases {
                try Task.checkCancellation()
                if !isFirstRequest {
                    try await sleepNanoseconds(nvdRequestSpacing)
                }
                isFirstRequest = false
                try Task.checkCancellation()

                do {
                    let cves = try await fetchAndDecodeNVD(alias: alias)
                    for cve in cves where matchesVendor(cve, config: config) {
                        guard let (severityString, score) = Self.extractCVSSSeverity(from: cve),
                              Self.appSeverity(forNVDSeverity: severityString) != nil else { continue }
                        let description = cve.descriptions.first { $0.lang == "en" }?.value ?? cve.id
                        collected[cve.id] = NVDCachedEntry(
                            cveID: cve.id,
                            title: String(description.prefix(120)),
                            description: description,
                            cvssBaseSeverity: severityString,
                            cvssBaseScore: score,
                            dateAdded: cve.published
                        )
                    }
                } catch is CancellationError {
                    throw ThreatRefreshError.cancelled
                } catch let error as ThreatRefreshError where error == .cancelled {
                    throw error
                } catch {
                    allAliasesSucceeded = false
                    logger.error("NVD fetch failed for vendor \(key, privacy: .public) alias \(alias, privacy: .public): \(String(describing: error), privacy: .public)")
                }
            }

            if allAliasesSucceeded {
                // Every alias for this vendor came back - `collected` is the
                // authoritative, complete result, so it replaces (not
                // merges with) whatever was cached before.
                nvdByVendor[key] = NVDVendorCache(fetchedAt: nowDate, entries: Array(collected.values))
            } else if !collected.isEmpty {
                var merged: [String: NVDCachedEntry] = Dictionary(
                    uniqueKeysWithValues: (nvdByVendor[key]?.entries ?? []).map { ($0.cveID, $0) }
                )
                for (id, entry) in collected { merged[id] = entry }
                let previousFetchedAt = nvdByVendor[key]?.fetchedAt ?? .distantPast
                nvdByVendor[key] = NVDVendorCache(fetchedAt: previousFetchedAt, entries: Array(merged.values))
            }
            // Falls through even when nothing succeeded for this vendor, so
            // its lastSeen sighting and checkedAt still get recorded - only
            // nvdByVendor[key] is left untouched in that case.
            persistNVDCheckpoint(lastSeen: lastSeen, checkedAt: nowDate)
        }
    }

    /// Persists the current `nvdByVendor`/lastSeen/checked-at state
    /// alongside whatever KEV data the cache already has, without
    /// disturbing it - mirrors `refresh()`'s "preserve the other source's
    /// data" behavior in the opposite direction. Failures are logged, not
    /// thrown: losing a just-fetched vendor's persistence on disk (it stays
    /// valid in memory for the rest of this refresh run) is better than
    /// aborting the remaining vendors in the queue over an unrelated
    /// disk-write issue.
    private func persistNVDCheckpoint(lastSeen: [String: Date], checkedAt: Date) {
        let newCache = buildCacheFile(
            kevFetchedAt: cache?.kevFetchedAt,
            catalogVersion: cache?.catalogVersion,
            catalogDateReleased: cache?.catalogDateReleased,
            entries: cache?.entries ?? [:],
            nvdVendors: nvdByVendor,
            nvdVendorLastSeen: lastSeen,
            nvdLastCheckedAt: checkedAt
        )
        do {
            try cacheStore.save(newCache)
            cache = newCache
        } catch {
            logger.error("Failed to persist NVD cache update: \(String(describing: error), privacy: .public)")
        }
    }

    /// Single construction point for `KEVCacheFile` so the KEV writer
    /// (`refresh()`) and the NVD writer (`persistNVDCheckpoint`) can't drift
    /// out of sync with each other's fields - each passes through whatever
    /// it isn't updating from `cache` unchanged, rather than two independent
    /// `KEVCacheFile(...)` call sites each risking silently resetting a
    /// field only the other one owns.
    private func buildCacheFile(
        kevFetchedAt: Date?,
        catalogVersion: String?,
        catalogDateReleased: String?,
        entries: [String: CISAKEVEntry],
        nvdVendors: [String: NVDVendorCache],
        nvdVendorLastSeen: [String: Date],
        nvdLastCheckedAt: Date?
    ) -> KEVCacheFile {
        KEVCacheFile(
            schemaVersion: KEVCacheFile.currentSchema,
            kevFetchedAt: kevFetchedAt,
            catalogVersion: catalogVersion,
            catalogDateReleased: catalogDateReleased,
            entries: entries,
            nvdVendors: nvdVendors,
            nvdVendorLastSeen: nvdVendorLastSeen,
            nvdLastCheckedAt: nvdLastCheckedAt
        )
    }

    /// Priority vendors first (in first-seen order, deduplicated), then
    /// every remaining eligible vendor in a stable alphabetical order -
    /// never raw dictionary iteration order, which Swift doesn't guarantee
    /// stable across runs.
    private func orderVendorKeys(allKeys: [String], priority: [String]) -> [String] {
        var seen = Set<String>()
        var ordered: [String] = []
        for key in priority where allKeys.contains(key) && seen.insert(key).inserted {
            ordered.append(key)
        }
        for key in allKeys.sorted() where seen.insert(key).inserted {
            ordered.append(key)
        }
        return ordered
    }

    private func fetchAndDecodeNVD(alias: String) async throws -> [NVDCVEDetail] {
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await fetchNVDFeed(alias)
        } catch is CancellationError {
            throw ThreatRefreshError.cancelled
        } catch let urlError as URLError where urlError.code == .cancelled {
            throw ThreatRefreshError.cancelled
        } catch let urlError as URLError {
            throw ThreatRefreshError.network(urlError.code)
        }

        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            let code = (response as? HTTPURLResponse)?.statusCode ?? -1
            throw ThreatRefreshError.badStatus(code)
        }
        guard let decoded = try? JSONDecoder().decode(NVDResponse.self, from: data) else {
            throw ThreatRefreshError.undecodable
        }
        return decoded.vulnerabilities.map(\.cve).filter { $0.vulnStatus != "Rejected" }
    }

    /// A CVE counts as belonging to `config`'s vendor only if (a) its
    /// English description contains one of the vendor's `nvdAliases` as a
    /// whole word - not a substring, which is what let a keyword search for
    /// "Calix" return a Mozilla bug crediting developer "Calixte Denizet" -
    /// or (b) one of its CPE configuration entries' vendor field is in the
    /// vendor's explicit `nvdCPEVendors` allowlist (NVD's CPE vendor
    /// strings often diverge from the brand name, e.g. Zhone's CPEs use
    /// `dasanzhone`/`zhone_technologies`, so this is populated by hand per
    /// vendor rather than derived from the alias list).
    private func matchesVendor(_ cve: NVDCVEDetail, config: VendorAdvisoryConfig) -> Bool {
        if let enDescription = cve.descriptions.first(where: { $0.lang == "en" })?.value {
            for alias in config.nvdAliases where Self.wordBoundaryMatch(text: enDescription, word: alias) {
                return true
            }
        }
        guard !config.nvdCPEVendors.isEmpty else { return false }
        let allowlist = Set(config.nvdCPEVendors.map { $0.lowercased() })
        for configuration in cve.configurations ?? [] {
            for node in configuration.nodes {
                for match in node.cpeMatch ?? [] {
                    // CPE 2.3 URI: cpe:2.3:<part>:<vendor>:<product>:...
                    let parts = match.criteria.split(separator: ":", omittingEmptySubsequences: false)
                    guard parts.count > 3 else { continue }
                    if allowlist.contains(String(parts[3]).lowercased()) { return true }
                }
            }
        }
        return false
    }

    private static func wordBoundaryMatch(text: String, word: String) -> Bool {
        guard !word.isEmpty else { return false }
        let pattern = "\\b\(NSRegularExpression.escapedPattern(for: word))\\b"
        guard let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive) else {
            return text.range(of: word, options: .caseInsensitive) != nil
        }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        return regex.firstMatch(in: text, range: range) != nil
    }

    /// Extracts CVSS base severity/score, preferring the newest metric
    /// version NVD reports and, within a version, a `Primary` (NVD-assigned)
    /// source over a `Secondary` (CNA-supplied) one - but accepting
    /// Secondary when Primary is absent, since a CVE still "Awaiting
    /// Analysis" often has only a CNA-supplied score and no NVD CPE
    /// configuration at all; requiring Primary-only would silently drop
    /// most of that data. CVSS v2's `baseSeverity` sits directly on the
    /// metric object, not nested under `cvssData` like v3.x/v4.0 - handled
    /// as a separate case below rather than a shared code path.
    static func extractCVSSSeverity(from cve: NVDCVEDetail) -> (severity: String, score: Double)? {
        func bestV3(_ metrics: [NVDMetricV3]?) -> (String, Double)? {
            guard let metrics, !metrics.isEmpty else { return nil }
            let chosen = metrics.first { $0.type == "Primary" } ?? metrics.first!
            return (chosen.cvssData.baseSeverity, chosen.cvssData.baseScore)
        }
        if let result = bestV3(cve.metrics?.cvssMetricV40) { return result }
        if let result = bestV3(cve.metrics?.cvssMetricV31) { return result }
        if let result = bestV3(cve.metrics?.cvssMetricV30) { return result }
        if let v2 = cve.metrics?.cvssMetricV2, !v2.isEmpty {
            let chosen = v2.first { $0.type == "Primary" } ?? v2.first!
            if let severity = chosen.baseSeverity {
                return (severity, chosen.cvssData.baseScore)
            }
        }
        return nil
    }

    /// CRITICAL/HIGH -> `.warning`, MEDIUM -> `.informational`, LOW or
    /// unrecognized -> filtered out entirely (returns nil). Nothing NVD
    /// reports ever reaches `.critical` - the same "vendor/manufacturer
    /// match isn't a confirmed vulnerability on this specific device"
    /// constraint that already caps KEV-sourced vendor matches at
    /// `.warning` applies regardless of source.
    static func appSeverity(forNVDSeverity severity: String) -> Severity? {
        switch severity.uppercased() {
        case "CRITICAL", "HIGH": return .warning
        case "MEDIUM": return .informational
        default: return nil
        }
    }

    // MARK: - Lookup

    /// Resolves `manufacturer` to a vendor and returns every KEV and/or NVD
    /// match for that vendor, newest first. A vendor with neither KEV nor
    /// NVD coverage yet, or a manufacturer that doesn't resolve to any
    /// vendor, returns `[]` - never a partial/ambiguous match.
    func vendorAdvisory(manufacturer: String?) async -> [VendorFinding] {
        ensureLoaded()
        guard let manufacturer, let (key, config) = resolveVendor(forManufacturer: manufacturer) else {
            return []
        }

        var results: [VendorFinding] = []

        let projects = Set(config.kevVendorProjects.map { $0.lowercased() })
        if !projects.isEmpty {
            results += kev.values
                .filter { projects.contains($0.vendorProject.lowercased()) }
                .map { entry in
                    VendorFinding(
                        cveID: entry.cveID, vendorKey: key, vendorDisplayName: config.displayName,
                        title: entry.vulnerabilityName, description: entry.shortDescription,
                        source: .kev, cvssBaseSeverity: nil, cvssBaseScore: nil, dateAdded: entry.dateAdded
                    )
                }
        }

        if let nvdCache = nvdByVendor[key] {
            results += nvdCache.entries.map { entry in
                VendorFinding(
                    cveID: entry.cveID, vendorKey: key, vendorDisplayName: config.displayName,
                    title: entry.title, description: entry.description,
                    source: .nvd, cvssBaseSeverity: entry.cvssBaseSeverity,
                    cvssBaseScore: entry.cvssBaseScore, dateAdded: entry.dateAdded
                )
            }
        }

        return results.sorted { ($0.dateAdded ?? "") > ($1.dateAdded ?? "") }
    }

    /// Tokenizes `manufacturer` (hyphens stripped before splitting, so
    /// "D-Link International" and "Tp-Link Technologies" both yield a
    /// "dlink"/"tplink" token instead of splitting on the hyphen) and
    /// matches WHOLE tokens only against each vendor's alias list - never a
    /// substring, which is what let "Cisco" match "Cisco-Linksys, LLC" and
    /// would equally let "arris" match "Harris Corporation" or "asus" match
    /// "ASUSTek" as an unintended hit. Ties (two vendors both matched, e.g.
    /// by aliases of equal length) resolve deterministically by preferring
    /// the longer alias, then the alphabetically-first vendor key - never by
    /// dictionary iteration order.
    private func resolveVendor(forManufacturer manufacturer: String) -> (key: String, config: VendorAdvisoryConfig)? {
        let stripped = manufacturer.replacingOccurrences(of: "-", with: "")
        let tokens = Set(
            stripped.lowercased()
                .components(separatedBy: CharacterSet.alphanumerics.inverted)
                .filter { !$0.isEmpty }
        )
        guard !tokens.isEmpty else { return nil }

        var best: (key: String, config: VendorAdvisoryConfig, aliasLength: Int)?
        for (key, config) in nistMap.vendorAdvisories {
            for alias in config.manufacturerAliases where tokens.contains(alias.lowercased()) {
                let length = alias.count
                if best == nil || length > best!.aliasLength || (length == best!.aliasLength && key < best!.key) {
                    best = (key, config, length)
                }
            }
        }
        return best.map { ($0.key, $0.config) }
    }
}

// MARK: - Decodable models (CISA KEV)

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
    /// Keyed by canonical vendor key (e.g. "dlink", "arris") - not the
    /// display name, since a vendor's KEV `vendorProject` string, its
    /// manufacturer-string aliases, and its display name can all differ.
    let vendorAdvisories: [String: VendorAdvisoryConfig]
}

/// One vendor's configuration for both live-KEV and live-NVD matching.
/// `kevVendorProjects` is an exact (case-insensitive) allowlist against
/// KEV's `vendorProject` field. `nvdAliases` are the keyword-search terms
/// queried against NVD for a vendor with no KEV coverage; `nvdCPEVendors`
/// is a secondary allowlist checked against each match's CPE configuration
/// vendor field, since a keyword hit alone (checked against the CVE
/// description as a whole word) can still miss entries whose description
/// never spells out the brand name but whose CPE data does.
struct VendorAdvisoryConfig: Decodable {
    let displayName: String
    let manufacturerAliases: [String]
    let kevVendorProjects: [String]
    let nvdCPEVendors: [String]
    let nvdAliases: [String]
}

// MARK: - Decodable models (NVD)

struct NVDResponse: Decodable {
    let vulnerabilities: [NVDVulnWrapper]
}

struct NVDVulnWrapper: Decodable {
    let cve: NVDCVEDetail
}

struct NVDCVEDetail: Decodable {
    let id: String
    let vulnStatus: String?
    let published: String?
    let descriptions: [NVDDescription]
    let metrics: NVDMetrics?
    let configurations: [NVDConfiguration]?
}

struct NVDDescription: Decodable {
    let lang: String
    let value: String
}

struct NVDMetrics: Decodable {
    let cvssMetricV40: [NVDMetricV3]?
    let cvssMetricV31: [NVDMetricV3]?
    let cvssMetricV30: [NVDMetricV3]?
    let cvssMetricV2: [NVDMetricV2]?
}

/// Shared shape for CVSS v3.0/v3.1/v4.0 metric entries - `baseSeverity`
/// lives inside `cvssData` for all three versions.
struct NVDMetricV3: Decodable {
    let type: String?
    let cvssData: NVDCvssDataV3
}
struct NVDCvssDataV3: Decodable {
    let baseScore: Double
    let baseSeverity: String
}

/// CVSS v2 puts `baseSeverity` directly on the metric object, not inside
/// `cvssData` (which only has `baseScore` for v2).
struct NVDMetricV2: Decodable {
    let type: String?
    let cvssData: NVDCvssDataV2
    let baseSeverity: String?
}
struct NVDCvssDataV2: Decodable {
    let baseScore: Double
}

struct NVDConfiguration: Decodable {
    let nodes: [NVDNode]
}
struct NVDNode: Decodable {
    let cpeMatch: [NVDCpeMatch]?
}
struct NVDCpeMatch: Decodable {
    let criteria: String
}
