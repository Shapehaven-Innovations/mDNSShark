// mDNSShark/Settings/PaywallPricing.swift
// Pure plan and pricing rules for PaywallView. Prices themselves always come from StoreKit.
import Foundation

enum PaywallPricing {
    /// Preselected plan, shown with the best-value badge.
    static let defaultPlan: PurchaseManager.Plan = .yearly

    /// Yearly price spread over 12 months, rounded half-up to 2 decimals (14.99 -> 1.25).
    static func monthlyEquivalent(ofYearly price: Decimal) -> Decimal {
        var perMonth = price / 12
        var rounded = Decimal()
        NSDecimalRound(&rounded, &perMonth, 2, .plain)
        return rounded
    }

    /// Primary button label for the selected plan. Lifetime never mentions a trial.
    static func buttonTitle(for plan: PurchaseManager.Plan, trialText: String?, lifetimePrice: String?) -> String {
        switch plan {
        case .yearly, .monthly:
            if let trialText { return "Start \(trialText)" }
            return "Subscribe"
        case .lifetime:
            if let lifetimePrice { return "Buy once for \(lifetimePrice)" }
            return "Buy once"
        }
    }
}
