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
}
