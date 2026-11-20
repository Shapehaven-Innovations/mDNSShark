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

    // MARK: - Trial gating and wording

    private let trial = "3-day free trial"
    private let yearlyBilled = "$14.99/year"
    private let monthlyBilled = "$1.99/month"
    private let lifetime = "$29.99"

    @Test("trial wording never shows for anyone on a plan")
    func trialHiddenWhenOnAPlan() {
        #expect(PaywallPricing.trialText(trial, currentPlan: nil) == trial)
        for plan in PurchaseManager.Plan.allCases {
            #expect(PaywallPricing.trialText(trial, currentPlan: plan) == nil)
        }
        #expect(PaywallPricing.trialText(nil, currentPlan: nil) == nil)
    }

    @Test("billed text joins price and period from the store")
    func billedText() {
        #expect(PaywallPricing.billedText(price: "$14.99", period: "year") == "$14.99/year")
        #expect(PaywallPricing.billedText(price: "$29.99", period: nil) == "$29.99")
        #expect(PaywallPricing.billedText(price: nil, period: "year") == nil)
    }

    @Test("row subtitles always state the amount")
    func rowSubtitlesStateAmount() {
        #expect(PaywallPricing.rowSubtitle(for: .yearly, trialText: trial, billed: yearlyBilled, lifetimePrice: lifetime)
                == "3-day free trial, then $14.99/year")
        #expect(PaywallPricing.rowSubtitle(for: .monthly, trialText: nil, billed: monthlyBilled, lifetimePrice: lifetime)
                == "Billed $1.99/month")
        #expect(PaywallPricing.rowSubtitle(for: .lifetime, trialText: trial, billed: nil, lifetimePrice: lifetime)
                == "$29.99 one-time purchase")
        #expect(PaywallPricing.rowSubtitle(for: .yearly, trialText: trial, billed: nil, lifetimePrice: lifetime) == nil)
    }

    @Test("offer line above the button leads with the billed amount")
    func offerLine() {
        #expect(PaywallPricing.offerLine(for: .yearly, currentPlan: nil, trialText: trial, billed: yearlyBilled, lifetimePrice: lifetime)
                == "3-day free trial, then $14.99/year")
        #expect(PaywallPricing.offerLine(for: .monthly, currentPlan: nil, trialText: nil, billed: monthlyBilled, lifetimePrice: lifetime)
                == "Billed $1.99/month, auto-renews")
        #expect(PaywallPricing.offerLine(for: .lifetime, currentPlan: .yearly, trialText: nil, billed: nil, lifetimePrice: lifetime)
                == "$29.99 one-time purchase")
        #expect(PaywallPricing.offerLine(for: .yearly, currentPlan: .lifetime, trialText: nil, billed: yearlyBilled, lifetimePrice: lifetime) == nil)
    }

    @Test("ineligible users never see trial wording anywhere")
    func ineligibleNeverSeesTrial() {
        let title = PaywallPricing.buttonTitle(for: .yearly, currentPlan: nil, trialText: nil, lifetimePrice: lifetime)
        let line = PaywallPricing.offerLine(for: .yearly, currentPlan: nil, trialText: nil, billed: yearlyBilled, lifetimePrice: lifetime) ?? ""
        let text = PaywallPricing.disclosure(for: .yearly, currentPlan: nil, trialText: nil, billed: yearlyBilled, lifetimePrice: lifetime)
        for s in [title, line, text] {
            #expect(!s.localizedCaseInsensitiveContains("trial"))
            #expect(!s.localizedCaseInsensitiveContains("free"))
        }
        #expect(title == "Subscribe")
        #expect(text.contains("$14.99/year"))
        #expect(text.contains("at purchase"))
    }

    // MARK: - Subscriber switching

    @Test("subscribers switching plans see Switch to, never a trial")
    func subscriberSwitchButton() {
        let title = PaywallPricing.buttonTitle(for: .yearly, currentPlan: .monthly, trialText: trial, lifetimePrice: lifetime)
        #expect(title == "Switch to Yearly")
        #expect(PaywallPricing.buttonTitle(for: .monthly, currentPlan: .yearly, trialText: trial, lifetimePrice: lifetime)
                == "Switch to Monthly")
        #expect(!title.localizedCaseInsensitiveContains("trial"))
        #expect(!title.localizedCaseInsensitiveContains("free"))
    }

    @Test("switch disclosure states the amount and Apple's change rules")
    func subscriberSwitchDisclosure() {
        let text = PaywallPricing.disclosure(for: .yearly, currentPlan: .monthly, trialText: trial,
                                             billed: yearlyBilled, lifetimePrice: lifetime)
        #expect(text.contains("Yearly: $14.99/year."))
        #expect(text.contains("subscription change rules"))
        #expect(!text.localizedCaseInsensitiveContains("trial"))
    }

    @Test("subscriber picking lifetime is told the subscription keeps renewing")
    func subscriberLifetimeDisclosure() {
        #expect(PaywallPricing.buttonTitle(for: .lifetime, currentPlan: .yearly, trialText: trial, lifetimePrice: lifetime)
                == "Buy once for $29.99")
        let text = PaywallPricing.disclosure(for: .lifetime, currentPlan: .yearly, trialText: trial,
                                             billed: nil, lifetimePrice: lifetime)
        #expect(text.contains("Lifetime: $29.99 once."))
        #expect(text.contains("keeps renewing until you cancel it"))
        // A new buyer is not told about a subscription they do not have.
        let fresh = PaywallPricing.disclosure(for: .lifetime, currentPlan: nil, trialText: trial,
                                              billed: nil, lifetimePrice: lifetime)
        #expect(!fresh.contains("keeps renewing"))
    }

    @Test("no trial wording in any copy once on a plan")
    func noTrialCopyOnAPlan() {
        for current in PurchaseManager.Plan.allCases {
            for plan in PurchaseManager.Plan.allCases where plan != current {
                let strings = [
                    PaywallPricing.buttonTitle(for: plan, currentPlan: current, trialText: trial, lifetimePrice: lifetime),
                    PaywallPricing.offerLine(for: plan, currentPlan: current, trialText: trial, billed: yearlyBilled, lifetimePrice: lifetime) ?? "",
                    PaywallPricing.disclosure(for: plan, currentPlan: current, trialText: trial, billed: yearlyBilled, lifetimePrice: lifetime),
                ]
                for s in strings {
                    #expect(!s.localizedCaseInsensitiveContains("trial"), "\(current) -> \(plan): \(s)")
                }
            }
        }
    }

    // MARK: - Lifetime owner

    @Test("lifetime owners get an inert button and no offer")
    func lifetimeOwnerCopy() {
        #expect(PaywallPricing.buttonTitle(for: .yearly, currentPlan: .lifetime, trialText: trial, lifetimePrice: lifetime)
                == "You have Lifetime access")
        #expect(PaywallPricing.offerLine(for: .yearly, currentPlan: .lifetime, trialText: trial, billed: yearlyBilled, lifetimePrice: lifetime) == nil)
        let text = PaywallPricing.disclosure(for: .yearly, currentPlan: .lifetime, trialText: trial, billed: yearlyBilled, lifetimePrice: lifetime)
        #expect(text == "Lifetime access is already on this Apple Account.")
    }

    // MARK: - Current plan row

    @Test("current plan row shows the renewal or end date, nothing when unknown")
    func currentPlanSubtitle() {
        let date = Date(timeIntervalSince1970: 1_795_000_000)
        let expected = date.formatted(date: .abbreviated, time: .omitted)
        #expect(PaywallPricing.currentPlanSubtitle(state: .active(renews: date)) == "Renews \(expected)")
        #expect(PaywallPricing.currentPlanSubtitle(state: .cancelled(expires: date)) == "Ends \(expected)")
        for state in [SubscriptionUIState.billingRetry, .expired, .none] {
            #expect(PaywallPricing.currentPlanSubtitle(state: state) == nil)
        }
    }
}
