// mDNSShark/Shared/PaywallCardDismissal.swift
// Remembers that the Packets tab's paywall card was closed. Permanent: it survives
// relaunches and version bumps, so the card never comes back once dismissed.
import Foundation

struct PaywallCardDismissal {
    static let key = "paywall.packetsCardDismissed"
    let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    var isDismissed: Bool {
        get { defaults.bool(forKey: Self.key) }
        nonmutating set { defaults.set(newValue, forKey: Self.key) }
    }
}
