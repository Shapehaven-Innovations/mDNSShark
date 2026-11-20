import Testing
import Foundation
@testable import mDNSShark

@Suite("Packets paywall card dismissal")
struct PaywallCardDismissalTests {
    private func freshDefaults() -> UserDefaults {
        UserDefaults(suiteName: "PaywallCardDismissalTests.\(UUID().uuidString)")!
    }

    @Test("not dismissed on a fresh install")
    func freshInstallShowsCard() {
        #expect(!PaywallCardDismissal(defaults: freshDefaults()).isDismissed)
    }

    @Test("dismissal persists for a later reader, as after a relaunch")
    func dismissalPersists() {
        let defaults = freshDefaults()
        PaywallCardDismissal(defaults: defaults).isDismissed = true
        #expect(PaywallCardDismissal(defaults: defaults).isDismissed)
        #expect(defaults.bool(forKey: PaywallCardDismissal.key))
    }
}
