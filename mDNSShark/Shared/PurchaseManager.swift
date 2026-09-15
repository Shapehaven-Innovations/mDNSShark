// mDNSShark/Shared/PurchaseManager.swift
// Add to the mDNSShark app target only (TLS Inspection purchase gate is a UI concern;
// the PacketTunnel extension reads the resulting SharedSettings.tlsInspectionUnlocked flag instead).
import Foundation
import StoreKit

enum TLSInspectionProduct {
    static let trial  = "beta.mDNSShark.tlsInspection.trial"
    static let unlock = "beta.mDNSShark.tlsInspection.unlock"
    static let trialDuration: TimeInterval = 3 * 24 * 60 * 60   // 3 days
}

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
            await self?.loadProducts()
            await self?.refreshEntitlements()
        }
    }

    deinit { updateListenerTask?.cancel() }

    func loadProducts() async {
        guard products.isEmpty else { return }
        do {
            let fetched = try await Product.products(for: [TLSInspectionProduct.trial, TLSInspectionProduct.unlock])
            for p in fetched { products[p.id] = p }
        } catch {
            lastError = error.localizedDescription
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
            lastError = "Product unavailable. Check your connection and try again."
            return
        }
        do {
            let result = try await product.purchase()
            switch result {
            case .success(let verification):
                await handle(verification)
            case .userCancelled, .pending:
                break
            @unknown default:
                break
            }
        } catch {
            lastError = error.localizedDescription
        }
    }

    private func handle(_ result: VerificationResult<Transaction>) async {
        guard case .verified(let transaction) = result else {
            lastError = "Purchase could not be verified. Please try again."
            return
        }
        await transaction.finish()
        await refreshEntitlements()
    }

    func refreshEntitlements() async {
        var unlocked = false
        var trialStart: Date?

        for await result in Transaction.currentEntitlements {
            guard case .verified(let transaction) = result else { continue }
            if transaction.productID == TLSInspectionProduct.unlock {
                unlocked = true
            } else if transaction.productID == TLSInspectionProduct.trial {
                trialStart = transaction.purchaseDate
            }
        }

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
