// mDNSShark/Settings/PaywallPricing.swift
// Pure plan and pricing rules for PaywallView. Prices themselves always come from StoreKit.
import Foundation

enum PaywallPricing {
    /// Preselected plan, shown with the best-value badge.
    static let defaultPlan: PurchaseManager.Plan = .yearly

    /// The plan to mark "Current plan". Lifetime wins over any subscription. A
    /// subscription counts while it is active or cancelled but still paid up; billing
    /// retry, expired and never-subscribed users get no marker, so every plan stays
    /// purchasable for them. An unknown subscription product id marks nothing.
    static func currentPlan(ownsLifetime: Bool,
                            subscriptionState: SubscriptionUIState,
                            subscriptionProductID: String?) -> PurchaseManager.Plan? {
        if ownsLifetime { return .lifetime }
        switch subscriptionState {
        case .active, .cancelled:
            guard let id = subscriptionProductID, let plan = PurchaseManager.Plan(productID: id),
                  plan != .lifetime else { return nil }
            return plan
        case .billingRetry, .expired, .none:
            return nil
        }
    }

    /// The plan preselected on open: the default, unless that is the current plan, in
    /// which case the lifetime upgrade. Never the current plan itself.
    static func defaultSelection(currentPlan: PurchaseManager.Plan?) -> PurchaseManager.Plan {
        currentPlan == defaultPlan ? .lifetime : defaultPlan
    }

    /// The plan to act on: the user's pick when it is offered and not already theirs,
    /// else the default selection, else the first offered plan that is not theirs.
    /// Falls back to the default selection when nothing is offered yet (no product
    /// loaded), so the disabled button still names a plan.
    static func effectiveSelection(selected: PurchaseManager.Plan?,
                                   currentPlan: PurchaseManager.Plan?,
                                   available: [PurchaseManager.Plan]) -> PurchaseManager.Plan {
        let purchasable = available.filter { $0 != currentPlan }
        if let selected, purchasable.contains(selected) { return selected }
        let preferred = defaultSelection(currentPlan: currentPlan)
        if purchasable.contains(preferred) || purchasable.isEmpty { return preferred }
        return purchasable[0]
    }

    /// Lifetime owners have nothing left to buy; the button stays visible but inert.
    static func purchasingDisabled(currentPlan: PurchaseManager.Plan?) -> Bool {
        currentPlan == .lifetime
    }

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
