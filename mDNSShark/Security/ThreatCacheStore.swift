// mDNSShark/Security/ThreatCacheStore.swift
import Foundation

/// A refreshed KEV catalog, filtered to the CVEs `nist_cpe_map.json` actually
/// references, persisted so a successful refresh survives relaunch.
struct KEVCacheFile: Codable, Equatable {
    static let currentSchema = 1

    let schemaVersion: Int
    let fetchedAt: Date
    let catalogVersion: String?
    let catalogDateReleased: String?
    let entries: [String: CISAKEVEntry]
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
