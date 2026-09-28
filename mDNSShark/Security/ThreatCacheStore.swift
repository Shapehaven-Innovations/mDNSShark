// mDNSShark/Security/ThreatCacheStore.swift
import Foundation

/// One NVD-sourced vendor match, already severity-filtered (LOW/unscored
/// entries never make it into this cache - see `ThreatDatabase.appSeverity`).
struct NVDCachedEntry: Codable, Equatable, Sendable {
    let cveID: String
    let title: String
    let description: String
    let cvssBaseSeverity: String?
    let cvssBaseScore: Double?
    let dateAdded: String?
}

/// One vendor's last-successful NVD fetch. Vendors refresh independently -
/// a vendor absent from this dictionary, or one whose entry is old, simply
/// hasn't been (re)fetched yet; it never blocks or is blocked by any other
/// vendor's fetch.
struct NVDVendorCache: Codable, Equatable, Sendable {
    let fetchedAt: Date
    let entries: [NVDCachedEntry]
}

/// A refreshed KEV catalog (filtered to referenced/vendor-claimed CVEs) plus
/// per-vendor NVD data, persisted so a successful refresh survives relaunch.
/// KEV and NVD fields are independent: `kevFetchedAt`/`entries` describe the
/// last successful KEV fetch (nil/empty if none has happened yet), and
/// `nvdVendors` accumulates one entry per vendor as each NVD fetch succeeds -
/// a KEV refresh preserves whatever `nvdVendors` already has, and vice versa.
struct KEVCacheFile: Codable, Equatable {
    static let currentSchema = 2

    let schemaVersion: Int
    let kevFetchedAt: Date?
    let catalogVersion: String?
    let catalogDateReleased: String?
    let entries: [String: CISAKEVEntry]
    let nvdVendors: [String: NVDVendorCache]
    /// When each vendor was last seen among scanned devices, keyed by
    /// canonical vendor key - drives the "seen within the last 30 days"
    /// fallback so an NVD-covered device that's temporarily offline doesn't
    /// immediately drop out of refresh scope. Optional (with a decode
    /// default of nil for older cache files) rather than a schema bump,
    /// since bumping `currentSchema` would silently discard a user's whole
    /// existing cache - including their already-fetched KEV data - on the
    /// next load.
    let nvdVendorLastSeen: [String: Date]?
    /// When the NVD refresh phase last completed, even with zero vendors to
    /// query - lets the status line say "checked, nothing to report" for
    /// the common case (no NVD-covered vendor on this LAN) instead of
    /// claiming NVD has never been refreshed. Optional for the same
    /// pre-existing-cache reason as above.
    let nvdLastCheckedAt: Date?
}

protocol ThreatCacheStoring: Sendable {
    func load() throws -> KEVCacheFile?
    func save(_ file: KEVCacheFile) throws
}

/// Stores the cache in the app container's Application Support directory
/// (not the app group: the PacketTunnel extension never reads threat data,
/// and a UserDefaults-backed suite like SharedSettings is the wrong shape
/// for a JSON blob). Excluded from backup since it's just a re-fetchable
/// cache, and protected until first unlock so a background-launched
/// refresh (if one is ever added) can still read it.
struct FileThreatCacheStore: ThreatCacheStoring {
    let fileURL: URL

    static func appDefault() -> FileThreatCacheStore {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("ThreatData", isDirectory: true)
        return FileThreatCacheStore(fileURL: base.appendingPathComponent("kev_cache.json"))
    }

    func load() throws -> KEVCacheFile? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return nil }
        let data = try Data(contentsOf: fileURL)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(KEVCacheFile.self, from: data)
    }

    func save(_ file: KEVCacheFile) throws {
        let dir = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        // Applied to the directory (not the file) since an atomic write
        // below replaces the file's inode on every save, which would drop
        // a per-file resource value.
        var dirURL = dir
        var excluded = URLResourceValues()
        excluded.isExcludedFromBackup = true
        try? dirURL.setResourceValues(excluded)

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(file)
        try data.write(to: fileURL, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }
}
