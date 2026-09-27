// mDNSSharkTests/ThreatDatabaseTestSupport.swift
import Foundation
@testable import mDNSShark

enum Fixture {
    /// A small bundled KEV snapshot: one real KEV entry (CVE-2020-9054),
    /// catalogVersion "2026.01.01".
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
        }
      ]
    }
    """.data(using: .utf8)!

    /// Referenced CVEs: CVE-2020-9054 (in bundled KEV), CVE-2011-2523
    /// (curated text, not in bundled KEV), CVE-2023-39238 (neither -
    /// falls back to the generic description).
    static let nistMapJSON = """
    {
      "serviceTypes": {
        "_ftp._tcp": {
          "cves": ["CVE-2020-9054", "CVE-2011-2523"],
          "description": "FTP transmits credentials in cleartext."
        }
      },
      "manufacturers": {
        "ASUS": {
          "cves": ["CVE-2023-39238"],
          "description": "ASUS router firmware has known vulnerabilities."
        }
      },
      "cves": {
        "CVE-2011-2523": {
          "title": "vsftpd 2.3.4 Backdoor",
          "description": "A tampered vsftpd 2.3.4 release contains a backdoor."
        }
      }
    }
    """.data(using: .utf8)!

    /// A live-feed-shaped payload with `count` entries, used for the
    /// "implausible feed" plausibility-floor tests and the happy-path
    /// refresh tests. `matching` are entries that should end up cached;
    /// padding entries exist purely to clear the `>= 1000` floor.
    static func liveFeedJSON(catalogVersion: String = "2026.02.01",
                              matching: [(cveID: String, name: String, desc: String)],
                              paddingCount: Int = 1200,
                              countOverride: Int? = nil) -> Data {
        var vulns: [[String: Any]] = matching.map {
            ["cveID": $0.cveID, "vendorProject": "Test", "product": "Test",
             "vulnerabilityName": $0.name, "shortDescription": $0.desc]
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
