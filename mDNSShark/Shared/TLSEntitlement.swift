// mDNSShark/Shared/TLSEntitlement.swift
// Pure mapping from verified StoreKit entitlements to the single access expiry
// mirrored in SharedSettings.tlsSubscriptionExpiry (read by the PacketTunnel extension).
import Foundation

enum TLSEntitlement {
    struct Entry: Equatable {
        let productID: String
        let expirationDate: Date?
        let isRevoked: Bool
    }

    /// Latest access expiry the entries grant, or nil when none grant access.
    /// Lifetime maps to `.distantFuture`, so it wins over any subscription.
    /// Revoked (refunded) entries and unknown products are ignored.
    static func expiry(from entries: [Entry]) -> Date? {
        var best: Date?
        for entry in entries where !entry.isRevoked {
            let granted: Date?
            if entry.productID == TLSInspectionProduct.lifetime {
                granted = .distantFuture
            } else if TLSInspectionProduct.subscriptions.contains(entry.productID) {
                granted = entry.expirationDate
            } else {
                granted = nil
            }
            if let granted { best = max(best ?? .distantPast, granted) }
        }
        return best
    }

    /// What to publish when currentEntitlements granted nothing (cold launch, offline,
    /// cache lag): the persisted expiry while it is still in the future, so paid access
    /// survives. A persisted lifetime (`.distantFuture`) never expires on its own, so it
    /// is dropped when the latest verified lifetime transaction shows a refund
    /// (`latestLifetimeRevoked == true`); `nil` means unknown (no or unverified
    /// transaction, e.g. offline) and keeps it.
    static func persistedFallback(_ persisted: Date?, now: Date, latestLifetimeRevoked: Bool?) -> Date? {
        guard let persisted, persisted > now else { return nil }
        if persisted == .distantFuture, latestLifetimeRevoked == true { return nil }
        return persisted
    }
}
