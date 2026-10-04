// mDNSShark/Shared/PurchaseManager.swift
// Add to the mDNSShark app target only (TLS Inspection purchase gate is a UI concern;
// the PacketTunnel extension reads the resulting SharedSettings.tlsAccessGranted value instead).
import Foundation
import StoreKit
import os

enum TLSInspectionProduct {
    /// Auto-renewable subscription with a free introductory trial configured in App Store Connect.
    static let monthly  = "beta.mDNSShark.tlsInspection.monthly"
    static let all: [String] = [monthly]
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
    @Published var lastError: String?

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
            productsLoaded = products[TLSInspectionProduct.monthly] != nil
            // Eligibility is otherwise only computed in refreshEntitlements, which can
            // run before products exist and leave the gate hiding a trial Apple will offer.
            if let sub = products[TLSInspectionProduct.monthly]?.subscription {
                trialEligible = await sub.isEligibleForIntroOffer
            }
        } catch {
            logger.error("loadProducts: \(error.localizedDescription) (\(String(describing: error)))")
            if reportErrors { lastError = error.localizedDescription }
        }
    }

    // MARK: - Display strings (always from the Store, never hardcoded)

    var monthlyPrice: String? { products[TLSInspectionProduct.monthly]?.displayPrice }

    /// Store-provided subscription title, e.g. "TLS Inspection Monthly".
    var productName: String? { products[TLSInspectionProduct.monthly]?.displayName }

    /// Billing period from the Store, e.g. "month" or "3 months".
    var periodText: String? {
        guard let period = products[TLSInspectionProduct.monthly]?.subscription?.subscriptionPeriod else { return nil }
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

    /// e.g. "3-day free trial"; nil unless the subscription has a free-trial introductory offer.
    var trialLengthText: String? {
        guard let offer = products[TLSInspectionProduct.monthly]?.subscription?.introductoryOffer,
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

    func subscribe() async {
        await purchase(productID: TLSInspectionProduct.monthly)
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
        if transaction.revocationDate != nil, transaction.productID == TLSInspectionProduct.monthly {
            logger.notice("handle: subscription revoked; clearing persisted expiry")
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
        if transaction.productID == TLSInspectionProduct.monthly,
           let e = transaction.expirationDate, e > (expiry ?? .distantPast) {
            logger.notice("handle: currentEntitlements lagged; applying subscription expiry directly")
            publish(expiry: e)
        }
    }

    func refreshEntitlements() async {
        var best: Date?
        var seen: [String] = []

        for await result in Transaction.currentEntitlements {
            guard case .verified(let transaction) = result, transaction.revocationDate == nil else { continue }
            seen.append(transaction.productID)
            if transaction.productID == TLSInspectionProduct.monthly, let e = transaction.expirationDate {
                best = max(best ?? .distantPast, e)
            }
        }

        var ui: SubscriptionUIState = .none
        if let sub = products[TLSInspectionProduct.monthly]?.subscription {
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
        // date; explicit revocations are cleared in handle().
        if best == nil, let persisted = SharedSettings.tlsSubscriptionExpiry, persisted > Date() {
            logger.notice("refreshEntitlements: subscription absent from currentEntitlements; keeping persisted expiry \(persisted)")
            best = persisted
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

        // Mirrored into the shared App Group suite so the PacketTunnel extension
        // (a separate process with no StoreKit entitlement checks of its own) can
        // gate on it, and so the next launch is seeded before StoreKit responds.
        SharedSettings.tlsSubscriptionExpiry = newExpiry
    }
}
