// mDNSShark/Shared/PurchaseManager.swift
// Add to the mDNSShark app target only (TLS Inspection purchase gate is a UI concern;
// the PacketTunnel extension reads the resulting SharedSettings.tlsAccessGranted value instead).
import Foundation
import StoreKit
import os

enum TLSInspectionProduct {
    /// Auto-renewable subscription with a free introductory trial configured in App Store Connect.
    static let monthly  = "beta.mDNSShark.tlsInspection.monthly"
    /// Auto-renewable, same subscription group as monthly (ranked above it), free introductory trial.
    static let yearly   = "beta.mDNSShark.tlsInspection.yearly"
    /// Non-consumable one-time purchase; no trial.
    static let lifetime = "beta.mDNSShark.tlsInspection.lifetime"
    static let all: [String] = [monthly, yearly, lifetime]
    static let subscriptions: [String] = [monthly, yearly]
}

// Every StoreKit outcome is logged so a "tapped the button and nothing happened"
// report can be pinned to a branch from the Xcode console (filter: "Purchase").
// `.userCancelled` is (correctly) silent in the UI, but Xcode's local StoreKit
// Testing on iOS 26.3+ runtimes has a known regression where purchase() returns
// `.userCancelled` immediately with no sheet (Apple forums 820991 / 826364,
// FB22774836), which is indistinguishable from a real cancel without this log.
private let logger = Logger(subsystem: "com.mDNSShark", category: "Purchase")

enum SubscriptionUIState: Equatable {
    case none
    case active(renews: Date)
    case cancelled(expires: Date)
    case billingRetry
    case expired
}

@MainActor
final class PurchaseManager: ObservableObject {
    static let shared = PurchaseManager()

    // Seeded from the last known StoreKit result (written by publish below) so a
    // relaunch shows the correct gate immediately instead of flashing the paywall
    // while Transaction.currentEntitlements resolves.
    @Published private(set) var expiry: Date? = SharedSettings.tlsSubscriptionExpiry
    @Published private(set) var subscriptionState: SubscriptionUIState = .none
    @Published private(set) var trialEligible = false
    @Published private(set) var productsLoaded = false
    /// True while the published expiry is the lifetime purchase's far-future date.
    @Published private(set) var ownsLifetime = SharedSettings.tlsSubscriptionExpiry == .distantFuture
    @Published var lastError: String?
    /// The Packets tab's paywall card was hidden. Held here, not in the view, because
    /// the tab view is recreated on every tab switch; resets on relaunch.
    @Published var paywallCardDismissed = false

    /// The three offers on the paywall. Yearly and monthly share one subscription group.
    enum Plan: CaseIterable {
        case yearly, monthly, lifetime

        var productID: String {
            switch self {
            case .yearly:   return TLSInspectionProduct.yearly
            case .monthly:  return TLSInspectionProduct.monthly
            case .lifetime: return TLSInspectionProduct.lifetime
            }
        }
    }

    var hasAccess: Bool {
        expiry.map { $0 > Date() } ?? false
    }

    private var products: [String: Product] = [:]
    private var updateListenerTask: Task<Void, Never>?

    private init() {
        updateListenerTask = Task { [weak self] in
            for await result in Transaction.updates {
                await self?.handle(result)
            }
        }
        Task { [weak self] in
            // Preload is best-effort: a failure here must not set lastError.
            // SettingsView's Store Error alert is driven by `lastError != nil`,
            // so a launch-time failure would pop an out-of-context alert the
            // first time Settings opens. purchase() re-fetches on demand and
            // reports its own errors.
            await self?.loadProducts(reportErrors: false)
            await self?.reconcileOwnership()
            await self?.refreshEntitlements()
        }
    }

    deinit { updateListenerTask?.cancel() }

    func loadProducts(reportErrors: Bool = true) async {
        // Fetch only what is still missing rather than skipping when the cache is non-empty.
        let missing = TLSInspectionProduct.all.filter { products[$0] == nil }
        guard !missing.isEmpty else { return }
        do {
            let fetched = try await Product.products(for: missing)
            for p in fetched { products[p.id] = p }
            let stillMissing = missing.filter { products[$0] == nil }
            logger.info("loadProducts: fetched \(fetched.map(\.id)) missing \(stillMissing)")
            if !stillMissing.isEmpty {
                // Product.products(for:) omits unknown IDs silently rather than
                // throwing. In StoreKit Testing this means the .storekit file
                // isn't active for this run or doesn't define the ID; in the
                // sandbox it means the ID isn't in App Store Connect or isn't
                // attached to the app version.
                logger.error("loadProducts: StoreKit returned no product for \(stillMissing); check the scheme's StoreKit Configuration is active for this run destination")
            }
            // True only when all three loaded; the paywall gates each plan on its own
            // product and uses this only to decide whether to fetch the missing ones again.
            productsLoaded = TLSInspectionProduct.all.allSatisfy { products[$0] != nil }
            // Eligibility is otherwise only computed in refreshEntitlements, which can
            // run before products exist and leave the gate hiding a trial Apple will offer.
            // Yearly and monthly share a group, so either product answers for both.
            if let sub = groupSubscription {
                trialEligible = await sub.isEligibleForIntroOffer
            }
        } catch {
            logger.error("loadProducts: \(error.localizedDescription) (\(String(describing: error)))")
            if reportErrors { lastError = error.localizedDescription }
        }
    }

    /// Any loaded product of the monthly/yearly subscription group; eligibility and
    /// status are per group, so it does not matter which one answers.
    private var groupSubscription: Product.SubscriptionInfo? {
        (products[TLSInspectionProduct.monthly] ?? products[TLSInspectionProduct.yearly])?.subscription
    }

    // MARK: - Display strings (always from the Store, never hardcoded)

    func product(for plan: Plan) -> Product? { products[plan.productID] }

    func displayPrice(for plan: Plan) -> String? { product(for: plan)?.displayPrice }

    /// e.g. "3-day free trial" from the plan's own introductory offer; nil for lifetime
    /// (no trial) and when this Apple ID is no longer eligible for the group's intro offer.
    func trialText(for plan: Plan) -> String? {
        guard plan != .lifetime, trialEligible else { return nil }
        return Self.freeTrialText(product(for: plan))
    }

    /// Yearly only: the Store price spread over 12 months, in the Store's currency format.
    func perMonthText(for plan: Plan) -> String? {
        guard plan == .yearly, let yearly = product(for: .yearly) else { return nil }
        return PaywallPricing.monthlyEquivalent(ofYearly: yearly.price).formatted(yearly.priceFormatStyle)
    }

    /// Billing period from the Store, e.g. "month" or "year"; nil for lifetime.
    func periodText(for plan: Plan) -> String? {
        guard let period = product(for: plan)?.subscription?.subscriptionPeriod else { return nil }
        let unit: String
        switch period.unit {
        case .day:   unit = "day"
        case .week:  unit = "week"
        case .month: unit = "month"
        case .year:  unit = "year"
        @unknown default: return nil
        }
        return period.value == 1 ? unit : "\(period.value) \(unit)s"
    }

    /// Cheapest per-month figure across yearly and monthly, for the Settings "See plans" row.
    var lowestPerMonthText: String? {
        var best: (amount: Decimal, text: String)?
        if let yearly = product(for: .yearly) {
            let amount = PaywallPricing.monthlyEquivalent(ofYearly: yearly.price)
            best = (amount, amount.formatted(yearly.priceFormatStyle))
        }
        if let monthly = product(for: .monthly), monthly.price < (best?.amount ?? .greatestFiniteMagnitude) {
            best = (monthly.price, monthly.displayPrice)
        }
        return best?.text
    }

    /// e.g. "3-day free trial"; nil unless the product has a free-trial introductory offer.
    private static func freeTrialText(_ product: Product?) -> String? {
        guard let offer = product?.subscription?.introductoryOffer,
              offer.paymentMode == .freeTrial else { return nil }
        let n = offer.period.value * offer.periodCount
        let unit: String
        switch offer.period.unit {
        case .day:   unit = "day"
        case .week:  unit = "week"
        case .month: unit = "month"
        case .year:  unit = "year"
        @unknown default: return nil
        }
        return "\(n)-\(unit) free trial"
    }

    // MARK: - Actions

    func buy(_ plan: Plan) async {
        await purchase(productID: plan.productID)
    }

    func restore() async {
        do {
            try await AppStore.sync()
            await reconcileOwnership()
            await refreshEntitlements()
        } catch {
            lastError = error.localizedDescription
        }
    }

    // MARK: - Internals

    // SharedSettings is an App Group UserDefaults suite, not scoped to any
    // Apple ID: a restored backup, a fresh install inheriting leftover App
    // Group state, or a switch to a different Apple ID can leave a stale
    // expiry on disk that refreshEntitlements() would otherwise carry forward (by design, to survive the StoreKit cache-lag
    // case). AppTransaction.appTransactionID is Apple's account-scoped
    // answer to "has this Apple ID obtained this app before": a mismatch
    // against the persisted owner means the state on disk belongs to someone
    // else and must be cleared before refreshEntitlements runs.
    private func reconcileOwnership() async {
        guard let result = try? await AppTransaction.shared,
              case .verified(let appTransaction) = result else {
            logger.notice("reconcileOwnership: AppTransaction unavailable/unverified; leaving persisted state as-is")
            return
        }
        let currentOwner = appTransaction.appTransactionID
        guard let persistedOwner = SharedSettings.ownerAppTransactionID, persistedOwner != currentOwner else {
            SharedSettings.ownerAppTransactionID = currentOwner
            return
        }
        logger.notice("reconcileOwnership: App Group state belongs to a different Apple ID; clearing persisted access state")
        SharedSettings.tlsSubscriptionExpiry = nil
        SharedSettings.ownerAppTransactionID = currentOwner
    }

    private func purchase(productID: String) async {
        if products[productID] == nil { await loadProducts() }
        guard let product = products[productID] else {
            logger.error("purchase(\(productID)): product not loaded, aborting")
            lastError = "Product unavailable. Check your connection and try again."
            return
        }
        let started = Date()
        do {
            let result = try await product.purchase()
            let elapsed = Date().timeIntervalSince(started)
            switch result {
            case .success(let verification):
                logger.info("purchase(\(productID)): success after \(elapsed, format: .fixed(precision: 2))s")
                await handle(verification)
            case .userCancelled:
                // Intentionally no user-facing error. A genuine cancel takes
                // human time; a sub-second .userCancelled with no sheet is the
                // StoreKit Testing regression described at the top of the file.
                logger.notice("purchase(\(productID)): userCancelled after \(elapsed, format: .fixed(precision: 2))s\(elapsed < 1 ? " (too fast for a real cancel; StoreKit Testing likely never presented a sheet)" : "")")
            case .pending:
                logger.notice("purchase(\(productID)): pending")
                lastError = "Purchase is pending approval (Ask to Buy, parental controls, or a required update) and hasn't completed yet. Check back once it's approved."
            @unknown default:
                logger.error("purchase(\(productID)): unknown PurchaseResult \(String(describing: result))")
            }
        } catch {
            logger.error("purchase(\(productID)): threw \(error.localizedDescription) (\(String(describing: error)))")
            lastError = error.localizedDescription
        }
    }

    private func handle(_ result: VerificationResult<Transaction>) async {
        guard case .verified(let transaction) = result else {
            if case .unverified(let tx, let verificationError) = result {
                logger.error("handle: unverified transaction product=\(tx.productID) reason=\(String(describing: verificationError))")
            }
            lastError = "Purchase could not be verified. Please try again."
            return
        }
        logger.info("handle: verified product=\(transaction.productID) id=\(transaction.id) purchaseDate=\(transaction.purchaseDate) revoked=\(transaction.revocationDate != nil)")
        // A revocation (refund) is the one positive signal that persisted access
        // must go: refreshEntitlements() deliberately keeps persisted state when
        // an entitlement is merely absent from currentEntitlements (cache lag).
        // refreshEntitlements() then recomputes, so a remaining valid entitlement
        // (e.g. a subscription after a refunded lifetime) restores access.
        if transaction.revocationDate != nil, TLSInspectionProduct.all.contains(transaction.productID) {
            logger.notice("handle: \(transaction.productID) revoked; clearing persisted expiry")
            SharedSettings.tlsSubscriptionExpiry = nil
        }
        await transaction.finish()
        await refreshEntitlements()
        applyIfMissing(transaction)
    }

    // Transaction.currentEntitlements is a local cache that can lag the transaction
    // StoreKit just handed us (Apple forums 820813 / 823454). If refreshEntitlements()
    // didn't see this transaction, apply it directly: it is already verified.
    private func applyIfMissing(_ transaction: Transaction) {
        guard transaction.revocationDate == nil else { return }
        if transaction.productID == TLSInspectionProduct.lifetime, expiry != .distantFuture {
            logger.notice("handle: currentEntitlements lagged; applying lifetime access directly")
            publish(expiry: .distantFuture)
        } else if TLSInspectionProduct.subscriptions.contains(transaction.productID),
           let e = transaction.expirationDate, e > (expiry ?? .distantPast) {
            logger.notice("handle: currentEntitlements lagged; applying subscription expiry directly")
            publish(expiry: e)
        }
    }

    func refreshEntitlements() async {
        var entries: [TLSEntitlement.Entry] = []

        for await result in Transaction.currentEntitlements {
            guard case .verified(let transaction) = result else { continue }
            entries.append(TLSEntitlement.Entry(productID: transaction.productID,
                                                expirationDate: transaction.expirationDate,
                                                isRevoked: transaction.revocationDate != nil))
        }
        let seen = entries.filter { !$0.isRevoked }.map(\.productID)
        // Lifetime maps to .distantFuture and so wins over any subscription.
        var best = TLSEntitlement.expiry(from: entries)

        // Subscription UI state comes from the monthly/yearly group only; a
        // lifetime-only owner stays at .none.
        var ui: SubscriptionUIState = .none
        if let sub = groupSubscription {
            trialEligible = await sub.isEligibleForIntroOffer
            if let status = try? await sub.status.first,
               case .verified(let info) = status.renewalInfo,
               case .verified(let tx) = status.transaction {
                let exp = tx.expirationDate ?? .now
                switch status.state {
                case .subscribed:
                    ui = info.willAutoRenew ? .active(renews: exp) : .cancelled(expires: exp)
                case .inGracePeriod:
                    // Access continues through the grace period.
                    if let g = info.gracePeriodExpirationDate { best = max(best ?? .distantPast, g) }
                    ui = .billingRetry
                case .inBillingRetryPeriod:
                    ui = .billingRetry
                default:
                    ui = .expired
                }
            }
        }
        subscriptionState = ui

        // An empty currentEntitlements (cold launch, offline) must not clear paid
        // access. Persisted state can only outlive the store by its own expiry
        // date; explicit revocations are cleared in handle(). A persisted lifetime
        // has no expiry of its own, so a refund that never reached handle() is
        // caught here from the latest lifetime transaction.
        if best == nil, let persisted = SharedSettings.tlsSubscriptionExpiry {
            var lifetimeRevoked: Bool?
            if persisted == .distantFuture,
               case .verified(let latest)? = await Transaction.latest(for: TLSInspectionProduct.lifetime) {
                lifetimeRevoked = latest.revocationDate != nil
            }
            best = TLSEntitlement.persistedFallback(persisted, now: Date(), latestLifetimeRevoked: lifetimeRevoked)
            if let best {
                logger.notice("refreshEntitlements: absent from currentEntitlements; keeping persisted expiry \(best)")
            } else if lifetimeRevoked == true {
                logger.notice("refreshEntitlements: latest lifetime transaction is revoked; dropping persisted lifetime access")
            }
        }
        logger.info("refreshEntitlements: currentEntitlements=\(seen) expiry=\(best.map { "\($0)" } ?? "nil")")
        publish(expiry: best)
    }

    private func publish(expiry newExpiry: Date?) {
        // Only assign (and thus only publish) on an actual change: @Published fires
        // objectWillChange on every assignment regardless of equality, and an
        // unconditional reassignment re-renders SettingsView at an arbitrary moment,
        // which can cancel an in-flight sheet presentation.
        if expiry != newExpiry { expiry = newExpiry }
        let lifetime = newExpiry == .distantFuture
        if ownsLifetime != lifetime { ownsLifetime = lifetime }

        // Mirrored into the shared App Group suite so the PacketTunnel extension
        // (a separate process with no StoreKit entitlement checks of its own) can
        // gate on it, and so the next launch is seeded before StoreKit responds.
        SharedSettings.tlsSubscriptionExpiry = newExpiry
    }
}
