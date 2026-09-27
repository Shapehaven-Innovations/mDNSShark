// mDNSSharkTests/ThreatDataStatusTests.swift
import Testing
import Foundation
@testable import mDNSShark

@Suite("ThreatDataStatus.summary")
struct ThreatDataStatusTests {
    private let day: TimeInterval = 24 * 60 * 60

    @Test("bundled and 5 days old gives the bundled text, not stale")
    func bundledFresh() {
        let now = Date()
        let status = ThreatDataStatus(
            bundledSnapshotDate: now.addingTimeInterval(-5 * day),
            bundledCatalogVersion: "2026.01.01",
            lastSuccessfulRefresh: nil,
            refreshedCatalogVersion: nil,
            checkedCVECount: 9
        )
        let summary = status.summary(now: now)
        #expect(summary.text.hasPrefix("CISA exploit data: bundled with this app"))
        #expect(!summary.isStale)
    }

    @Test("bundled and 40 days old is stale")
    func bundledStale() {
        let now = Date()
        let status = ThreatDataStatus(
            bundledSnapshotDate: now.addingTimeInterval(-40 * day),
            bundledCatalogVersion: "2026.01.01",
            lastSuccessfulRefresh: nil,
            refreshedCatalogVersion: nil,
            checkedCVECount: 9
        )
        let summary = status.summary(now: now)
        #expect(summary.isStale)
        #expect(summary.text.contains("Over 30 days old."))
    }

    @Test("refreshed yesterday gives the refreshed text, not stale")
    func refreshedFresh() {
        let now = Date()
        let status = ThreatDataStatus(
            bundledSnapshotDate: now.addingTimeInterval(-400 * day),
            bundledCatalogVersion: "2026.01.01",
            lastSuccessfulRefresh: now.addingTimeInterval(-1 * day),
            refreshedCatalogVersion: "2026.09.25",
            checkedCVECount: 9
        )
        let summary = status.summary(now: now)
        #expect(summary.text.hasPrefix("CISA exploit data: refreshed"))
        #expect(!summary.isStale)
    }
}
