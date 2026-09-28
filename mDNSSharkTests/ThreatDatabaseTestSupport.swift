// mDNSSharkTests/ThreatDatabaseTestSupport.swift
import Foundation
@testable import mDNSShark

enum Fixture {
    /// A small bundled KEV snapshot: CVE-2020-9054 (Zyxel, service-type
    /// referenced) and CVE-2023-3333 (ASUS, vendor-advisory only - not
    /// referenced by any service type), catalogVersion "2026.01.01".
    static let bundledKEVJSON = """
    {
      "title": "Test bundled snapshot",
      "catalogVersion": "2026.01.01",
      "dateReleased": "2026-01-01T00:00:00.0000Z",
      "snapshotDate": "2026-01-01",
      "vulnerabilities": [
        {
          "cveID": "CVE-2020-9054",
          "vendorProject": "Zyxel",
          "product": "NAS",
          "vulnerabilityName": "Zyxel NAS OS Command Injection",
          "shortDescription": "Zyxel NAS devices allow unauthenticated command injection."
        },
        {
          "cveID": "CVE-2023-3333",
          "vendorProject": "ASUS",
          "product": "Router",
          "vulnerabilityName": "ASUS Router RCE",
          "shortDescription": "Some ASUS routers allow unauthenticated remote code execution.",
          "dateAdded": "2023-06-01"
        }
      ]
    }
    """.data(using: .utf8)!

    /// `vendorAdvisories` has two KEV-backed vendors ("zyxel", matching
    /// bundled entry CVE-2020-9054; "asus", matching bundled entry
    /// CVE-2023-3333) and one NVD-only placeholder ("arris", empty
    /// `kevVendorProjects` - PR2 territory, should never produce a match in
    /// these tests).
    static let nistMapJSON = """
    {
      "vendorAdvisories": {
        "zyxel": {
          "displayName": "Zyxel",
          "manufacturerAliases": ["zyxel"],
          "kevVendorProjects": ["Zyxel"],
          "nvdCPEVendors": [],
          "nvdAliases": []
        },
        "asus": {
          "displayName": "ASUS",
          "manufacturerAliases": ["asus", "asustek"],
          "kevVendorProjects": ["ASUS"],
          "nvdCPEVendors": [],
          "nvdAliases": []
        },
        "arris": {
          "displayName": "Arris/CommScope",
          "manufacturerAliases": ["arris", "commscope"],
          "kevVendorProjects": [],
          "nvdCPEVendors": [],
          "nvdAliases": []
        }
      }
    }
    """.data(using: .utf8)!

    /// Same shape as `nistMapJSON`, but "arris" has real NVD wiring
    /// (aliases + CPE-vendor allowlist) instead of the empty placeholder -
    /// for PR2's NVD-matching tests. Also adds "calix", whose alias is
    /// deliberately a substring of an unrelated name ("Calixte") to drive
    /// the word-boundary-filter test.
    static let nistMapWithNVDJSON = """
    {
      "vendorAdvisories": {
        "zyxel": {
          "displayName": "Zyxel",
          "manufacturerAliases": ["zyxel"],
          "kevVendorProjects": ["Zyxel"],
          "nvdCPEVendors": [],
          "nvdAliases": []
        },
        "arris": {
          "displayName": "Arris/CommScope",
          "manufacturerAliases": ["arris", "commscope"],
          "kevVendorProjects": [],
          "nvdCPEVendors": ["arris", "commscope"],
          "nvdAliases": ["Arris", "CommScope"]
        },
        "calix": {
          "displayName": "Calix",
          "manufacturerAliases": ["calix"],
          "kevVendorProjects": [],
          "nvdCPEVendors": ["calix"],
          "nvdAliases": ["Calix"]
        }
      }
    }
    """.data(using: .utf8)!

    /// A live-feed-shaped payload with `count` entries, used for the
    /// "implausible feed" plausibility-floor tests and the happy-path
    /// refresh tests. `matching` are entries that should end up cached -
    /// refresh() only caches entries whose vendorProject is claimed by some
    /// vendorAdvisories entry, so each defaults to "Zyxel" (claimed in both
    /// `nistMapJSON` and `nistMapWithNVDJSON`); pass `vendorProjects`
    /// (parallel to `matching`, by index) to override per-entry for tests
    /// that need a mix of claimed/unclaimed vendors. Padding entries exist
    /// purely to clear the `>= 1000` floor and use an unclaimed vendor.
    static func liveFeedJSON(catalogVersion: String = "2026.02.01",
                              matching: [(cveID: String, name: String, desc: String)],
                              vendorProjects: [String]? = nil,
                              paddingCount: Int = 1200,
                              countOverride: Int? = nil) -> Data {
        var vulns: [[String: Any]] = matching.enumerated().map { index, entry in
            let vendorProject = vendorProjects?.indices.contains(index) == true ? vendorProjects![index] : "Zyxel"
            return ["cveID": entry.cveID, "vendorProject": vendorProject, "product": "Test",
                    "vulnerabilityName": entry.name, "shortDescription": entry.desc]
        }
        for i in 0..<paddingCount {
            vulns.append([
                "cveID": "CVE-9999-\(10000 + i)", "vendorProject": "Padding", "product": "Padding",
                "vulnerabilityName": "Padding Entry \(i)", "shortDescription": "Not referenced by the map."
            ])
        }
        let payload: [String: Any] = [
            "title": "Test live feed",
            "catalogVersion": catalogVersion,
            "dateReleased": "2026-02-01T00:00:00.0000Z",
            "count": countOverride ?? vulns.count,
            "vulnerabilities": vulns
        ]
        return try! JSONSerialization.data(withJSONObject: payload)
    }

    static func httpResponse(status: Int = 200, url: URL = URL(string: "https://www.cisa.gov/kev.json")!) -> URLResponse {
        HTTPURLResponse(url: url, statusCode: status, httpVersion: nil, headerFields: nil)!
    }

    static func nvdHTTPResponse(status: Int = 200) -> URLResponse {
        HTTPURLResponse(url: URL(string: "https://services.nvd.nist.gov/rest/json/cves/2.0")!,
                         statusCode: status, httpVersion: nil, headerFields: nil)!
    }

    /// Builds a minimal NVD `/cves/2.0` response body with one CVE. Pass
    /// `cvssV31`/`cvssV2` to attach a metric of that version; omit both for
    /// a CVE with no extractable severity at all (the "filtered out"
    /// case). `cpeVendor`, when set, adds one `configurations` node whose
    /// CPE criteria vendor field is that string.
    static func nvdCVEJSON(
        id: String,
        description: String,
        vulnStatus: String = "Analyzed",
        cvssV31: (severity: String, score: Double)? = nil,
        cvssV2: (severity: String?, score: Double)? = nil,
        cpeVendor: String? = nil
    ) -> Data {
        var cve: [String: Any] = [
            "id": id,
            "vulnStatus": vulnStatus,
            "published": "2026-06-01T00:00:00.000",
            "descriptions": [["lang": "en", "value": description]]
        ]
        var metrics: [String: Any] = [:]
        if let cvssV31 {
            metrics["cvssMetricV31"] = [[
                "type": "Primary",
                "cvssData": ["baseScore": cvssV31.score, "baseSeverity": cvssV31.severity]
            ]]
        }
        if let cvssV2 {
            var metric: [String: Any] = ["type": "Primary", "cvssData": ["baseScore": cvssV2.score]]
            if let severity = cvssV2.severity { metric["baseSeverity"] = severity }
            metrics["cvssMetricV2"] = [metric]
        }
        if !metrics.isEmpty { cve["metrics"] = metrics }
        if let cpeVendor {
            cve["configurations"] = [
                ["nodes": [["cpeMatch": [["criteria": "cpe:2.3:h:\(cpeVendor):some_product:*:*:*:*:*:*:*:*"]]]]]
            ]
        }
        let payload: [String: Any] = ["vulnerabilities": [["cve": cve]]]
        return try! JSONSerialization.data(withJSONObject: payload)
    }

    static func emptyNVDResponse() -> Data {
        try! JSONSerialization.data(withJSONObject: ["vulnerabilities": [] as [Any]])
    }
}

/// Records every NVD alias queried, in order, and returns a per-alias
/// canned response (or throws `StubError` if the alias has none queued).
/// Lets tests assert both *what* was queried and *how many* requests were
/// made, without racing real NVD rate-limit timing.
actor RecordingNVDFetcher {
    private(set) var queriedAliases: [String] = []
    private var responses: [String: Result<(Data, URLResponse), Error>] = [:]
    var onQuery: (@Sendable (String) -> Void)?

    func setResponse(_ result: Result<(Data, URLResponse), Error>, forAlias alias: String) {
        responses[alias] = result
    }

    func fetch(_ alias: String) async throws -> (Data, URLResponse) {
        queriedAliases.append(alias)
        onQuery?(alias)
        guard let result = responses[alias] else { throw StubError() }
        return try result.get()
    }
}

/// In-memory `ThreatCacheStoring` for tests. Not actor-isolated (tests call
/// it from a single `ThreatDatabase` actor context at a time in practice),
/// but marked `@unchecked Sendable` with a lock since the protocol requires
/// `Sendable` and the actor may hop threads between calls.
final class MockThreatCacheStore: ThreatCacheStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var stored: KEVCacheFile?
    var saveError: Error?
    private(set) var savedFiles: [KEVCacheFile] = []

    init(initial: KEVCacheFile? = nil) {
        self.stored = initial
    }

    func load() throws -> KEVCacheFile? {
        lock.lock(); defer { lock.unlock() }
        return stored
    }

    func save(_ file: KEVCacheFile) throws {
        lock.lock(); defer { lock.unlock() }
        if let saveError { throw saveError }
        stored = file
        savedFiles.append(file)
    }

    var lastSaved: KEVCacheFile? {
        lock.lock(); defer { lock.unlock() }
        return savedFiles.last
    }
}

struct StubError: Error {}

/// A fetch closure that suspends until `release()` is called, so tests can
/// deterministically exercise "a second refresh while the first is still
/// in flight" and "capture starts mid-fetch, cancel the task" without
/// racing real network timing.
actor GatedFetcher {
    private var released = false
    private(set) var callCount = 0
    var result: Result<(Data, URLResponse), Error> = .failure(StubError())

    func fetch() async throws -> (Data, URLResponse) {
        callCount += 1
        while !released {
            try Task.checkCancellation()
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        try Task.checkCancellation()
        return try result.get()
    }

    func release() {
        released = true
    }

    func setResult(_ result: Result<(Data, URLResponse), Error>) {
        self.result = result
    }
}

func immediateFetcher(_ result: @escaping @Sendable () throws -> (Data, URLResponse)) -> KEVFeedFetcher {
    { try result() }
}
