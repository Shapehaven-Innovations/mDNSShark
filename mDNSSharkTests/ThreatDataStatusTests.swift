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
            vendorCount: 20
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
            vendorCount: 20
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
            vendorCount: 20
        )
        let summary = status.summary(now: now)
        #expect(summary.text.hasPrefix("CISA exploit data: refreshed"))
        #expect(!summary.isStale)
    }

    @Test("NVD never checked gives the not-yet-refreshed text")
    func nvdNeverChecked() {
        let now = Date()
        let status = ThreatDataStatus(
            bundledSnapshotDate: now.addingTimeInterval(-5 * day),
            bundledCatalogVersion: "2026.01.01",
            lastSuccessfulRefresh: nil,
            refreshedCatalogVersion: nil,
            vendorCount: 20,
            nvdVendorCount: 9
        )
        #expect(status.summary(now: now).text.contains("NVD: not yet refreshed."))
    }

    @Test("NVD checked with no covered vendor present gives the checked-not-refreshed text, distinct from never-checked")
    func nvdCheckedNoCoveredVendors() {
        let now = Date()
        let status = ThreatDataStatus(
            bundledSnapshotDate: now.addingTimeInterval(-5 * day),
            bundledCatalogVersion: "2026.01.01",
            lastSuccessfulRefresh: nil,
            refreshedCatalogVersion: nil,
            vendorCount: 20,
            nvdLastSuccessfulRefresh: nil,
            nvdVendorCount: 9,
            nvdLastCheckedAt: now.addingTimeInterval(-1 * day)
        )
        let text = status.summary(now: now).text
        #expect(text.contains("NVD: checked"))
        #expect(text.contains("no covered vendors on this network"))
        #expect(!text.contains("NVD: not yet refreshed."))
    }

    @Test("a vendor actually refreshed takes precedence over the checked-only state")
    func nvdRefreshedTakesPrecedenceOverChecked() {
        let now = Date()
        let status = ThreatDataStatus(
            bundledSnapshotDate: now.addingTimeInterval(-5 * day),
            bundledCatalogVersion: "2026.01.01",
            lastSuccessfulRefresh: nil,
            refreshedCatalogVersion: nil,
            vendorCount: 20,
            nvdLastSuccessfulRefresh: now.addingTimeInterval(-2 * day),
            nvdVendorCount: 9,
            nvdLastCheckedAt: now.addingTimeInterval(-2 * day)
        )
        let text = status.summary(now: now).text
        #expect(text.contains("NVD: refreshed"))
        #expect(!text.contains("no covered vendors"))
    }
}
