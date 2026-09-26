// mDNSShark/Shared/PurchaseManager.swift
// Add to the mDNSShark app target only (TLS Inspection purchase gate is a UI concern;
// the PacketTunnel extension reads the resulting SharedSettings.tlsInspectionUnlocked flag instead).
import Foundation
import StoreKit
import os

enum TLSInspectionProduct {
    static let trial  = "beta.mDNSShark.tlsInspection.trial"
    static let unlock = "beta.mDNSShark.tlsInspection.unlock"
    static let all: [String] = [trial, unlock]
    static let trialDuration: TimeInterval = 3 * 24 * 60 * 60   // 3 days
}

// Every StoreKit outcome is logged so a "tapped the button and nothing happened"
// report can be pinned to a branch from the Xcode console (filter: "Purchase").
// Without this the purchase flow is invisible: StoreKit's own logs are private and
// `.userCancelled` is (correctly) silent in the UI — but Xcode's local StoreKit
// Testing on iOS 26.3+ runtimes has a known regression where purchase() returns
// `.userCancelled` immediately with no sheet (Apple forums 820991 / 826364,
// FB22774836), which is indistinguishable from a real cancel without this log.
private let logger = Logger(subsystem: "com.mDNSShark", category: "Purchase")

enum TrialState: Equatable {
    case notStarted
    case active(daysRemaining: Int)
    case expired
}

@MainActor
final class PurchaseManager: ObservableObject {
    static let shared = PurchaseManager()

    // Seeded from the last known StoreKit result (written by refreshEntitlements below)
    // so relaunch after backgrounding shows the correct gate immediately instead of
    // flashing the paywall while Transaction.currentEntitlements resolves.
    @Published private(set) var isUnlocked = SharedSettings.tlsInspectionUnlocked
    @Published private(set) var trialState: TrialState = PurchaseManager.computeTrialState(from: SharedSettings.tlsTrialStartDate)
    @Published var lastError: String?

    var hasAccess: Bool {
        if isUnlocked { return true }
        if case .active = trialState { return true }
        return false
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
            // first time Settings opens — and if that presentation is dropped
            // (view not in the hierarchy yet), the binding stays true and every
            // later, user-initiated error is swallowed because there's no
            // false→true transition left to present on. purchase() re-fetches
            // on demand and reports its own errors.
            await self?.loadProducts(reportErrors: false)
            await self?.refreshEntitlements()
        }
    }

    deinit { updateListenerTask?.cancel() }

    func loadProducts(reportErrors: Bool = true) async {
        // Fetch whatever is still missing, not "anything if the cache is empty":
        // a partial result (e.g. only one of the two IDs came back) would
        // otherwise pin the other product as permanently unavailable.
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
                // sandbox it means the ID isn't in App Store Connect.
                logger.error("loadProducts: StoreKit returned no product for \(stillMissing) — check the scheme's StoreKit Configuration is active for this run destination")
            }
        } catch {
            logger.error("loadProducts: \(error.localizedDescription) (\(String(describing: error)))")
            if reportErrors { lastError = error.localizedDescription }
        }
    }

    var unlockPrice: String {
        products[TLSInspectionProduct.unlock]?.displayPrice ?? "$4.99"
    }

    func startTrial() async {
        await purchase(productID: TLSInspectionProduct.trial)
    }

    func purchaseUnlock() async {
        await purchase(productID: TLSInspectionProduct.unlock)
    }

    func restore() async {
        do {
            try await AppStore.sync()
            await refreshEntitlements()
        } catch {
            lastError = error.localizedDescription
        }
    }

    // MARK: - Internals

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
                logger.notice("purchase(\(productID)): userCancelled after \(elapsed, format: .fixed(precision: 2))s\(elapsed < 1 ? " — too fast for a real cancel; StoreKit Testing likely never presented a sheet" : "")")
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
        await transaction.finish()
        await refreshEntitlements()
        applyIfMissing(transaction)
    }

    // Transaction.currentEntitlements is a local cache that can lag the transaction
    // StoreKit just handed us (Apple forums 820813 / 823454: it sometimes emits
    // nothing until a sync or reboot). If refreshEntitlements() didn't see this
    // transaction, apply it directly so the UI unlocks now instead of on some
    // later launch — the transaction is already verified, so it is authoritative.
    private func applyIfMissing(_ transaction: Transaction) {
        guard transaction.revocationDate == nil else { return }
        switch transaction.productID {
        case TLSInspectionProduct.unlock where !isUnlocked:
            logger.notice("handle: currentEntitlements lagged; applying unlock directly")
            publish(unlocked: true, trialStart: SharedSettings.tlsTrialStartDate)
        case TLSInspectionProduct.trial where trialState == .notStarted:
            logger.notice("handle: currentEntitlements lagged; applying trial start directly")
            publish(unlocked: isUnlocked, trialStart: transaction.purchaseDate)
        default:
            break
        }
    }

    func refreshEntitlements() async {
        var unlocked = false
        var trialStart: Date?

        var seen: [String] = []
        for await result in Transaction.currentEntitlements {
            guard case .verified(let transaction) = result else { continue }
            seen.append(transaction.productID)
            if transaction.productID == TLSInspectionProduct.unlock {
                unlocked = true
            } else if transaction.productID == TLSInspectionProduct.trial {
                trialStart = transaction.purchaseDate
            }
        }
        logger.info("refreshEntitlements: currentEntitlements=\(seen) unlocked=\(unlocked) trialStart=\(trialStart.map { "\($0)" } ?? "nil")")
        publish(unlocked: unlocked, trialStart: trialStart)
    }

    private func publish(unlocked: Bool, trialStart: Date?) {
        // Only assign (and thus only publish) on an actual change — @Published fires
        // objectWillChange on every assignment regardless of equality, and this method
        // runs on every launch/foreground even when nothing changed (e.g. no purchase
        // yet). An unconditional reassignment re-renders SettingsView at an arbitrary
        // moment, which can land mid-transaction on an in-flight sheet presentation
        // (e.g. the TLS warning sheet) and cause iOS to cancel it immediately.
        let newTrialState = Self.computeTrialState(from: trialStart)
        if isUnlocked != unlocked { isUnlocked = unlocked }
        if trialState != newTrialState { trialState = newTrialState }

        // Mirrored into the shared App Group suite so the PacketTunnel extension
        // (a separate process with no StoreKit entitlement checks of its own) can
        // gate on it without talking to StoreKit itself, and so PurchaseManager
        // can seed an accurate TrialState on next launch before StoreKit responds.
        SharedSettings.tlsInspectionUnlocked = hasAccess
        SharedSettings.tlsTrialStartDate = trialStart
    }

    private static func computeTrialState(from start: Date?) -> TrialState {
        guard let start else { return .notStarted }
        let elapsed = Date().timeIntervalSince(start)
        guard elapsed < TLSInspectionProduct.trialDuration else { return .expired }
        let remaining = TLSInspectionProduct.trialDuration - elapsed
        return .active(daysRemaining: Int(ceil(remaining / 86400)))
    }
}
