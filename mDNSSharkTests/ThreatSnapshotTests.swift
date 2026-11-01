// mDNSSharkTests/ThreatSnapshotTests.swift
import Testing
import Foundation
@testable import mDNSShark

@Suite("ThreatSnapshot")
struct ThreatSnapshotTests {

    private func makeDatabase() -> ThreatDatabase {
        ThreatDatabase(bundledKEVData: Fixture.bundledKEVJSON, nistMapData: Fixture.nistMapJSON,
                       cacheStore: MockThreatCacheStore(), fetchFeed: { throw StubError() })
    }

    @Test("snapshot lookups match the actor's vendorAdvisory for matching, hyphenated and unknown manufacturers")
    func snapshotMatchesActor() async {
        let db = makeDatabase()
        let snapshot = await db.snapshot()
        for manufacturer in ["ASUSTek COMPUTER INC.", "ASUS-TEK Computer Inc.", "Harris Corporation", "Apple Inc.", nil] {
            let fromActor = await db.vendorAdvisory(manufacturer: manufacturer)
            let fromSnapshot = snapshot.vendorAdvisory(manufacturer: manufacturer)
            #expect(fromSnapshot.map(\.cveID) == fromActor.map(\.cveID))
            #expect(fromSnapshot.map(\.source) == fromActor.map(\.source))
        }
    }

    @Test("a snapshot taken before a refresh keeps the old data")
    func snapshotIsAValueCopy() async throws {
        let feed = Fixture.liveFeedJSON(catalogVersion: "2026.03.01", matching: [
            ("CVE-2023-3333", "ASUS Router RCE", "desc"),
            ("CVE-2026-4444", "ASUS New Bug", "new desc"),
        ], vendorProjects: ["ASUS", "ASUS"])
        let db = ThreatDatabase(bundledKEVData: Fixture.bundledKEVJSON, nistMapData: Fixture.nistMapJSON,
                                cacheStore: MockThreatCacheStore(),
                                fetchFeed: immediateFetcher { (feed, Fixture.httpResponse()) })
        let before = await db.snapshot()
        _ = try await db.refresh()
        let after = await db.snapshot()
        #expect(before.vendorAdvisory(manufacturer: "ASUS").map(\.cveID) == ["CVE-2023-3333"])
        #expect(Set(after.vendorAdvisory(manufacturer: "ASUS").map(\.cveID)) == ["CVE-2023-3333", "CVE-2026-4444"])
    }
}
