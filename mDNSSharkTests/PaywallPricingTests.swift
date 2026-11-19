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
}
