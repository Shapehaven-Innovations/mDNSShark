import Testing
import Foundation
@testable import mDNSShark

@Suite("Paywall pricing rules")
struct PaywallPricingTests {
    @Test("$14.99 a year is $1.25 a month")
    func monthlyEquivalentOf1499Is125() {
        #expect(PaywallPricing.monthlyEquivalent(ofYearly: Decimal(string: "14.99")!) == Decimal(string: "1.25")!)
    }

    @Test("yearly is preselected")
    func defaultPlanIsYearly() {
        #expect(PaywallPricing.defaultPlan == .yearly)
    }

    @Test("lifetime button never mentions a trial")
    func lifetimeButtonNeverMentionsTrial() {
        let title = PaywallPricing.buttonTitle(for: .lifetime, trialText: "3-day free trial", lifetimePrice: "$29.99")
        #expect(title == "Buy once for $29.99")
        #expect(!title.localizedCaseInsensitiveContains("trial"))
        #expect(!title.localizedCaseInsensitiveContains("free"))
    }

    @Test("eligible yearly starts the trial")
    func yearlyButtonUsesTrialTextWhenEligible() {
        #expect(PaywallPricing.buttonTitle(for: .yearly, trialText: "3-day free trial", lifetimePrice: "$29.99")
                == "Start 3-day free trial")
    }

    @Test("ineligible yearly says Subscribe")
    func ineligibleYearlySaysSubscribe() {
        #expect(PaywallPricing.buttonTitle(for: .yearly, trialText: nil, lifetimePrice: "$29.99") == "Subscribe")
        #expect(PaywallPricing.buttonTitle(for: .monthly, trialText: nil, lifetimePrice: nil) == "Subscribe")
    }

    @Test("lifetime without a price says Buy once")
    func lifetimeWithoutPriceSaysBuyOnce() {
        #expect(PaywallPricing.buttonTitle(for: .lifetime, trialText: nil, lifetimePrice: nil) == "Buy once")
    }

    // MARK: - Current plan marker

    private let renews = Date().addingTimeInterval(86_400 * 30)

    @Test("active yearly subscriber is on the yearly plan")
    func activeYearlyIsCurrent() {
        #expect(PaywallPricing.currentPlan(ownsLifetime: false,
                                           subscriptionState: .active(renews: renews),
                                           subscriptionProductID: TLSInspectionProduct.yearly) == .yearly)
    }

    @Test("active monthly subscriber is on the monthly plan")
    func activeMonthlyIsCurrent() {
        #expect(PaywallPricing.currentPlan(ownsLifetime: false,
                                           subscriptionState: .active(renews: renews),
                                           subscriptionProductID: TLSInspectionProduct.monthly) == .monthly)
    }

    @Test("cancelled but still paid subscription is still the current plan")
    func cancelledStillPaidIsCurrent() {
        #expect(PaywallPricing.currentPlan(ownsLifetime: false,
                                           subscriptionState: .cancelled(expires: renews),
                                           subscriptionProductID: TLSInspectionProduct.monthly) == .monthly)
    }

    @Test("lifetime owner is on lifetime, even with a subscription")
    func lifetimeWinsOverSubscription() {
        #expect(PaywallPricing.currentPlan(ownsLifetime: true,
                                           subscriptionState: .none,
                                           subscriptionProductID: nil) == .lifetime)
        #expect(PaywallPricing.currentPlan(ownsLifetime: true,
                                           subscriptionState: .active(renews: renews),
                                           subscriptionProductID: TLSInspectionProduct.yearly) == .lifetime)
    }

    @Test("billing retry, expired and never-subscribed mark no plan")
    func noMarkerWithoutPaidAccess() {
        for state in [SubscriptionUIState.billingRetry, .expired, .none] {
            #expect(PaywallPricing.currentPlan(ownsLifetime: false,
                                               subscriptionState: state,
                                               subscriptionProductID: TLSInspectionProduct.yearly) == nil)
        }
    }

    @Test("unknown or missing subscription product marks no plan")
    func unknownProductMarksNothing() {
        #expect(PaywallPricing.currentPlan(ownsLifetime: false,
                                           subscriptionState: .active(renews: renews),
                                           subscriptionProductID: nil) == nil)
        #expect(PaywallPricing.currentPlan(ownsLifetime: false,
                                           subscriptionState: .active(renews: renews),
                                           subscriptionProductID: "beta.mDNSShark.other") == nil)
        #expect(PaywallPricing.currentPlan(ownsLifetime: false,
                                           subscriptionState: .active(renews: renews),
                                           subscriptionProductID: TLSInspectionProduct.lifetime) == nil)
    }

    @Test("plans map back from their product ids")
    func planFromProductID() {
        for plan in PurchaseManager.Plan.allCases {
            #expect(PurchaseManager.Plan(productID: plan.productID) == plan)
        }
        #expect(PurchaseManager.Plan(productID: "nope") == nil)
    }

    // MARK: - Default selection

    @Test("default selection never lands on the current plan")
    func defaultSelectionAvoidsCurrentPlan() {
        for plan in PurchaseManager.Plan.allCases {
            #expect(PaywallPricing.defaultSelection(currentPlan: plan) != plan)
        }
        #expect(PaywallPricing.defaultSelection(currentPlan: nil) == PaywallPricing.defaultPlan)
    }

    @Test("yearly subscribers are offered lifetime, others the default")
    func defaultSelectionPerCurrentPlan() {
        #expect(PaywallPricing.defaultSelection(currentPlan: .yearly) == .lifetime)
        #expect(PaywallPricing.defaultSelection(currentPlan: .monthly) == .yearly)
        #expect(PaywallPricing.defaultSelection(currentPlan: .lifetime) == .yearly)
    }

    @Test("effective selection never lands on the current plan")
    func effectiveSelectionAvoidsCurrentPlan() {
        let all = PurchaseManager.Plan.allCases
        for current in all {
            for picked in all + [nil] {
                #expect(PaywallPricing.effectiveSelection(selected: picked, currentPlan: current, available: all) != current)
            }
        }
    }

    @Test("effective selection honours a purchasable pick and falls back otherwise")
    func effectiveSelectionFallbacks() {
        let all = PurchaseManager.Plan.allCases
        #expect(PaywallPricing.effectiveSelection(selected: .monthly, currentPlan: nil, available: all) == .monthly)
        #expect(PaywallPricing.effectiveSelection(selected: nil, currentPlan: nil, available: all) == .yearly)
        // Picked plan is the current one: fall back to the default selection.
        #expect(PaywallPricing.effectiveSelection(selected: .yearly, currentPlan: .yearly, available: all) == .lifetime)
        // Preferred plan not loaded: first purchasable plan that did load.
        #expect(PaywallPricing.effectiveSelection(selected: nil, currentPlan: .yearly, available: [.yearly, .monthly]) == .monthly)
        // Nothing loaded: still names a plan for the disabled button.
        #expect(PaywallPricing.effectiveSelection(selected: nil, currentPlan: nil, available: []) == .yearly)
    }

    @Test("only lifetime owners have purchasing disabled")
    func purchasingDisabledOnlyForLifetime() {
        #expect(PaywallPricing.purchasingDisabled(currentPlan: .lifetime))
        #expect(!PaywallPricing.purchasingDisabled(currentPlan: .yearly))
        #expect(!PaywallPricing.purchasingDisabled(currentPlan: .monthly))
        #expect(!PaywallPricing.purchasingDisabled(currentPlan: nil))
    }
}
