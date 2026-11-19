import Testing
import Foundation
@testable import mDNSShark

@Suite("TLS entitlement mapping")
struct TLSEntitlementTests {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let day: TimeInterval = 86_400

    private func entry(_ id: String, expires: Date? = nil, revoked: Bool = false) -> TLSEntitlement.Entry {
        TLSEntitlement.Entry(productID: id, expirationDate: expires, isRevoked: revoked)
    }

    @Test("lifetime maps to distant future")
    func lifetimeGivesDistantFuture() {
        #expect(TLSEntitlement.expiry(from: [entry(TLSInspectionProduct.lifetime)]) == .distantFuture)
    }

    @Test("lifetime wins over an expired subscription")
    func lifetimeBeatsExpiredSubscription() {
        let entries = [
            entry(TLSInspectionProduct.monthly, expires: now.addingTimeInterval(-day)),
            entry(TLSInspectionProduct.lifetime),
        ]
        #expect(TLSEntitlement.expiry(from: entries) == .distantFuture)
    }

    @Test("latest subscription expiry wins")
    func latestSubscriptionExpiryWins() {
        let monthly = now.addingTimeInterval(30 * day)
        let yearly = now.addingTimeInterval(365 * day)
        let entries = [
            entry(TLSInspectionProduct.monthly, expires: monthly),
            entry(TLSInspectionProduct.yearly, expires: yearly),
        ]
        #expect(TLSEntitlement.expiry(from: entries) == yearly)
    }

    @Test("revoked lifetime is ignored when a subscription remains")
    func revokedLifetimeIgnored() {
        let monthly = now.addingTimeInterval(30 * day)
        let entries = [
            entry(TLSInspectionProduct.lifetime, revoked: true),
            entry(TLSInspectionProduct.monthly, expires: monthly),
        ]
        #expect(TLSEntitlement.expiry(from: entries) == monthly)
    }

    @Test("revoked lifetime alone gives no access")
    func revokedLifetimeAlone() {
        #expect(TLSEntitlement.expiry(from: [entry(TLSInspectionProduct.lifetime, revoked: true)]) == nil)
    }

    @Test("unknown products are ignored")
    func unknownProductIgnored() {
        let entries = [entry("com.example.other", expires: now.addingTimeInterval(day))]
        #expect(TLSEntitlement.expiry(from: entries) == nil)
    }

    @Test("no entries means no access")
    func emptyIsNil() {
        #expect(TLSEntitlement.expiry(from: []) == nil)
    }

    @Test("unexpired persisted subscription expiry is kept")
    func fallbackKeepsUnexpiredSubscription() {
        let persisted = now.addingTimeInterval(day)
        #expect(TLSEntitlement.persistedFallback(persisted, now: now, latestLifetimeRevoked: nil) == persisted)
        // A revoked lifetime says nothing about a persisted subscription date.
        #expect(TLSEntitlement.persistedFallback(persisted, now: now, latestLifetimeRevoked: true) == persisted)
    }

    @Test("expired or missing persisted expiry gives no access")
    func fallbackDropsExpired() {
        #expect(TLSEntitlement.persistedFallback(now.addingTimeInterval(-day), now: now, latestLifetimeRevoked: nil) == nil)
        #expect(TLSEntitlement.persistedFallback(nil, now: now, latestLifetimeRevoked: nil) == nil)
    }

    @Test("persisted lifetime is kept offline and when not revoked")
    func fallbackKeepsLifetimeUnlessRevoked() {
        #expect(TLSEntitlement.persistedFallback(.distantFuture, now: now, latestLifetimeRevoked: nil) == .distantFuture)
        #expect(TLSEntitlement.persistedFallback(.distantFuture, now: now, latestLifetimeRevoked: false) == .distantFuture)
    }

    @Test("persisted lifetime is dropped when the latest lifetime transaction is revoked")
    func fallbackDropsRevokedLifetime() {
        #expect(TLSEntitlement.persistedFallback(.distantFuture, now: now, latestLifetimeRevoked: true) == nil)
    }
}
