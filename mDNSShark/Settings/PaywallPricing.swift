// mDNSShark/Settings/PaywallPricing.swift
// Pure plan and pricing rules for PaywallView. Prices themselves always come from StoreKit.
import Foundation

enum PaywallPricing {
    typealias Plan = PurchaseManager.Plan

    /// Preselected plan, shown with the best-value badge.
    static let defaultPlan: Plan = .yearly

    static let manageSubscriptionsPath = "Settings > Apple Account > Subscriptions"

    /// Yearly price spread over 12 months, rounded half-up to 2 decimals (14.99 -> 1.25).
    static func monthlyEquivalent(ofYearly price: Decimal) -> Decimal {
        var perMonth = price / 12
        var rounded = Decimal()
        NSDecimalRound(&rounded, &perMonth, 2, .plain)
        return rounded
    }

    static func name(of plan: Plan) -> String {
        switch plan {
        case .yearly:   return "Yearly"
        case .monthly:  return "Monthly"
        case .lifetime: return "Lifetime"
        }
    }

    // MARK: - Current plan

    /// The plan to mark "Current plan". Lifetime wins over any subscription. A
    /// subscription counts while it is active or cancelled but still paid up; billing
    /// retry, expired and never-subscribed users get no marker, so every plan stays
    /// purchasable for them. An unknown subscription product id marks nothing.
    static func currentPlan(ownsLifetime: Bool,
                            subscriptionState: SubscriptionUIState,
                            subscriptionProductID: String?) -> Plan? {
        if ownsLifetime { return .lifetime }
        switch subscriptionState {
        case .active, .cancelled:
            guard let id = subscriptionProductID, let plan = Plan(productID: id),
                  plan != .lifetime else { return nil }
            return plan
        case .billingRetry, .expired, .none:
            return nil
        }
    }

    /// The plan preselected on open: the default, unless that is the current plan, in
    /// which case the lifetime upgrade. Never the current plan itself.
    static func defaultSelection(currentPlan: Plan?) -> Plan {
        currentPlan == defaultPlan ? .lifetime : defaultPlan
    }

    /// The plan to act on: the user's pick when it is offered and not already theirs,
    /// else the default selection, else the first offered plan that is not theirs.
    /// Falls back to the default selection when nothing is offered yet (no product
    /// loaded), so the disabled button still names a plan.
    static func effectiveSelection(selected: Plan?, currentPlan: Plan?, available: [Plan]) -> Plan {
        let purchasable = available.filter { $0 != currentPlan }
        if let selected, purchasable.contains(selected) { return selected }
        let preferred = defaultSelection(currentPlan: currentPlan)
        if purchasable.contains(preferred) || purchasable.isEmpty { return preferred }
        return purchasable[0]
    }

    /// Lifetime owners have nothing left to buy; the button stays visible but inert.
    static func purchasingDisabled(currentPlan: Plan?) -> Bool {
        currentPlan == .lifetime
    }

    /// What the current-plan row says under its name: the renewal or end date from
    /// the subscription status, nothing when that is unknown (or for lifetime).
    static func currentPlanSubtitle(state: SubscriptionUIState) -> String? {
        switch state {
        case .active(let renews):    return "Renews \(renews.formatted(date: .abbreviated, time: .omitted))"
        case .cancelled(let expires): return "Ends \(expires.formatted(date: .abbreviated, time: .omitted))"
        case .billingRetry, .expired, .none: return nil
        }
    }

    // MARK: - Trial and billing wording

    /// Trial wording is shown only to users StoreKit reports as eligible (the caller
    /// passes nil otherwise) who are on no plan at all: a subscriber or lifetime owner
    /// never sees a trial offer, whatever eligibility says.
    static func trialText(_ storeTrialText: String?, currentPlan: Plan?) -> String? {
        currentPlan == nil ? storeTrialText : nil
    }

    /// The billed amount with its period, e.g. "$14.99/year"; nil without a price.
    static func billedText(price: String?, period: String?) -> String? {
        guard let price else { return nil }
        return period.map { "\(price)/\($0)" } ?? price
    }

    /// Plan row subtitle. The amount always appears, trial wording only when allowed.
    static func rowSubtitle(for plan: Plan, trialText: String?, billed: String?, lifetimePrice: String?) -> String? {
        switch plan {
        case .yearly, .monthly:
            guard let billed else { return nil }
            if let trialText { return "\(trialText.capitalizedFirst), then \(billed)" }
            return "Billed \(billed)"
        case .lifetime:
            return lifetimePrice.map { "\($0) one-time purchase" }
        }
    }

    /// The line directly above the primary button (guideline 3.1.2: the billed amount
    /// is at least as prominent as any trial wording). Nil for a lifetime owner.
    static func offerLine(for plan: Plan, currentPlan: Plan?, trialText: String?,
                          billed: String?, lifetimePrice: String?) -> String? {
        if purchasingDisabled(currentPlan: currentPlan) { return nil }
        switch plan {
        case .lifetime:
            return lifetimePrice.map { "\($0) one-time purchase" }
        case .yearly, .monthly:
            guard let billed else { return nil }
            if let trialText = Self.trialText(trialText, currentPlan: currentPlan) {
                return "\(trialText.capitalizedFirst), then \(billed)"
            }
            return "Billed \(billed), auto-renews"
        }
    }

    /// Primary button label. Lifetime never mentions a trial; neither does a switch
    /// between subscriptions.
    static func buttonTitle(for plan: Plan, currentPlan: Plan?, trialText: String?, lifetimePrice: String?) -> String {
        if purchasingDisabled(currentPlan: currentPlan) { return "You have Lifetime access" }
        switch plan {
        case .lifetime:
            if let lifetimePrice { return "Buy once for \(lifetimePrice)" }
            return "Buy once"
        case .yearly, .monthly:
            if currentPlan != nil { return "Switch to \(name(of: plan))" }
            if let trialText = Self.trialText(trialText, currentPlan: currentPlan) { return "Start \(trialText)" }
            return "Subscribe"
        }
    }

    static func buttonTitle(for plan: Plan, trialText: String?, lifetimePrice: String?) -> String {
        buttonTitle(for: plan, currentPlan: nil, trialText: trialText, lifetimePrice: lifetimePrice)
    }

    /// Guideline 3.1.2 disclosure for the selected plan: billed amount, auto-renewal,
    /// charge timing and how to cancel. Subscribers switching plans are told the change
    /// follows Apple's rules; subscribers buying lifetime that their subscription keeps
    /// renewing until cancelled.
    static func disclosure(for plan: Plan, currentPlan: Plan?, trialText: String?,
                           billed: String?, lifetimePrice: String?) -> String {
        if purchasingDisabled(currentPlan: currentPlan) {
            return "Lifetime access is already on this Apple Account."
        }
        let trialText = Self.trialText(trialText, currentPlan: currentPlan)
        switch plan {
        case .lifetime:
            var text = lifetimePrice.map { "Lifetime: \($0) once. " } ?? ""
            text += "One-time purchase. No subscription. Charged to your Apple Account at purchase."
            if currentPlan != nil {
                text += " Your current subscription keeps renewing until you cancel it in \(manageSubscriptionsPath)."
            }
            return text
        case .yearly, .monthly:
            var text = ""
            if let billed {
                text += "\(name(of: plan)): \(billed)\(trialText != nil ? " after the trial" : ""). "
            }
            text += "Auto-renews until cancelled. "
            if currentPlan != nil {
                text += "Switching follows Apple's subscription change rules: an upgrade starts now, a downgrade at the end of the current period. "
            } else {
                text += "Charged to your Apple Account \(trialText != nil ? "when the trial ends" : "at purchase"). "
            }
            text += "Cancel at least 24 hours before renewal in \(manageSubscriptionsPath)."
            return text
        }
    }
}

extension String {
    var capitalizedFirst: String { prefix(1).uppercased() + dropFirst() }
}
