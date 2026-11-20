// mDNSShark/Settings/PaywallView.swift
// Three-plan TLS Inspection paywall sheet, opened from the Packets tab and Settings.
// Every price shown comes from StoreKit via PurchaseManager, never hard-coded.
import SwiftUI

struct PaywallView: View {
    @ObservedObject var purchase: PurchaseManager
    @Environment(\.dismiss) private var dismiss
    /// The user's explicit pick; nil until they tap a row, so the preselection can
    /// follow the current plan once StoreKit reports it.
    @State private var selected: PurchaseManager.Plan?
    @State private var inFlight = false
    @State private var loading = false

    // Vertical rhythm, scaled with Dynamic Type so the gaps grow with the text.
    /// Clears the grab handle and the close button (12pt inset + ~28pt glyph).
    @ScaledMetric(relativeTo: .title2) private var topInset: CGFloat = 56
    /// Minimum gap between the sheet's sections: header, features, plans, button.
    @ScaledMetric(relativeTo: .body) private var sectionGap: CGFloat = 24
    /// Most a section gap grows to when the sheet is taller than the content; the
    /// header keeps its feature list closer than the plans and the button.
    @ScaledMetric(relativeTo: .body) private var sectionGapMax: CGFloat = 64
    @ScaledMetric(relativeTo: .body) private var headerGapMax: CGFloat = 40
    /// Gap inside a section: between plan rows, button and disclosure, disclosure and links.
    @ScaledMetric(relativeTo: .body) private var itemGap: CGFloat = 12
    @ScaledMetric(relativeTo: .body) private var bottomInset: CGFloat = 20
    /// Plan row insets and the badge that overhangs the row's top edge, scaled so the
    /// badge keeps clearing the plan name at accessibility sizes.
    @ScaledMetric(relativeTo: .body) private var rowVerticalPadding: CGFloat = 12
    @ScaledMetric(relativeTo: .caption2) private var badgeOverhang: CGFloat = 9

    init(purchase: PurchaseManager) {
        self.purchase = purchase
    }

    var body: some View {
        // The sheet height drives the layout: when the content is shorter than the
        // sheet, the section gaps grow (up to sectionGapMax) so the content spreads
        // over the sheet instead of bunching up under the grab handle; whatever is
        // left after that is split above and below. When the content is taller
        // (iPhone SE, accessibility text sizes) the gaps stay at their minimum and
        // the content scrolls.
        GeometryReader { proxy in
            ScrollView {
                VStack(spacing: 0) {
                    header
                    sectionSpacer(max: headerGapMax)
                    features
                    sectionSpacer(max: sectionGapMax)
                    plans
                    if availablePlans.isEmpty {
                        loadingState
                            .padding(.top, itemGap)
                    }
                    sectionSpacer(max: sectionGapMax)
                    primaryButton
                    Text(disclosure)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.top, itemGap)
                    links
                        .padding(.top, itemGap)
                }
                .padding(.horizontal, 20)
                .padding(.top, topInset)
                .padding(.bottom, bottomInset)
                .frame(minHeight: proxy.size.height)
            }
        }
        .background(Color(.systemGroupedBackground).ignoresSafeArea())
        .overlay(alignment: .topTrailing) {
            Button { dismiss() } label: {
                Image(systemName: "xmark.circle.fill")
                    .font(.title2)
                    .symbolRenderingMode(.hierarchical)
                    .foregroundColor(.secondary)
            }
            .accessibilityLabel("Close")
            .padding(12)
        }
        .presentationDragIndicator(.visible)
        // The launch-time fetch can fail (offline, sandbox); retry so prices are never missing.
        .task { await reload(reportErrors: false) }
        // Close once a purchase lands. A current subscriber already has access, so
        // watch the expiry (lifetime or a yearly switch changes it), not hasAccess alone.
        .onChange(of: purchase.expiry) { _, _ in
            if purchase.hasAccess { dismiss() }
        }
        .alert("Store Error", isPresented: Binding(
            get: { purchase.lastError != nil },
            set: { if !$0 { purchase.lastError = nil } }
        ), actions: { Button("OK") { purchase.lastError = nil } },
           message: { Text(purchase.lastError ?? "") })
    }

    // MARK: - Sections

    /// A gap that grows with spare sheet height, between sectionGap and `max`.
    private func sectionSpacer(max: CGFloat) -> some View {
        Spacer(minLength: sectionGap)
            .frame(maxHeight: max)
    }

    private var header: some View {
        VStack(spacing: 6) {
            Text("TLS Inspection")
                .font(.title2.weight(.bold))
            Text("Decrypt and inspect HTTPS on this device.")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
    }

    private var features: some View {
        VStack(alignment: .leading, spacing: 8) {
            feature("Read HTTPS requests and responses")
            feature("Works with your own trusted CA certificate")
            feature("Cancel anytime, or buy once")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func feature(_ text: String) -> some View {
        Label {
            Text(text).font(.subheadline)
        } icon: {
            Image(systemName: "checkmark").foregroundColor(AppColors.secure)
        }
    }

    private var plans: some View {
        VStack(spacing: itemGap) {
            // Only plans whose product loaded are offered, so one missing product
            // (e.g. lifetime not yet live) does not block the others. With none
            // loaded, all rows show as disabled placeholders above Retry.
            ForEach(availablePlans.isEmpty ? PurchaseManager.Plan.allCases : availablePlans, id: \.self) { plan in
                if plan == currentPlan {
                    currentPlanRow(plan)
                } else {
                    planRow(plan)
                }
            }
        }
        // Room for the badge that overhangs the first row's top edge.
        .padding(.top, badgeOverhang)
        .disabled(availablePlans.isEmpty || inFlight)
    }

    private func planRow(_ plan: PurchaseManager.Plan) -> some View {
        let isSelected = current == plan
        return Button { selected = plan } label: {
            planRowContent(plan, subtitle: subtitle(of: plan))
                .background(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(isSelected ? AppColors.info.opacity(0.12) : Color(.secondarySystemGroupedBackground))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .stroke(isSelected ? AppColors.info : Color(.separator), lineWidth: isSelected ? 2 : 1)
                )
                .overlay(alignment: .topLeading) {
                    if plan == PaywallPricing.defaultPlan {
                        badge("BEST VALUE", fill: AppColors.secure, text: .black)
                    }
                }
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }

    /// The plan the user is already on: not a button, muted fill, marked so it still
    /// reads as one of the three offers.
    private func currentPlanRow(_ plan: PurchaseManager.Plan) -> some View {
        planRowContent(plan, subtitle: "Your current plan")
            .background(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(Color(.tertiarySystemGroupedBackground))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .strokeBorder(style: StrokeStyle(lineWidth: 1, dash: [5, 4]))
                    .foregroundColor(Color(.separator))
            )
            .overlay(alignment: .topLeading) {
                badge("CURRENT PLAN", fill: Color(.systemGray2), text: .white)
            }
            .accessibilityElement(children: .combine)
            .accessibilityValue("Current plan")
    }

    private func planRowContent(_ plan: PurchaseManager.Plan, subtitle: String) -> some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(name(of: plan)).font(.headline)
                Text(subtitle)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 2) {
                // Guideline 3.1.2(c): the billed amount outranks any trial wording.
                if let price = purchase.displayPrice(for: plan) {
                    Text(price).font(.title3.weight(.bold))
                }
                if let detail = priceDetail(of: plan) {
                    Text(detail)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, rowVerticalPadding)
        .frame(maxWidth: .infinity)
    }

    private func badge(_ title: String, fill: Color, text: Color) -> some View {
        Text(title)
            .font(.caption2.weight(.heavy))
            .foregroundColor(text)
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .background(Capsule().fill(fill))
            .offset(x: 12, y: -badgeOverhang)
    }

    @ViewBuilder
    private var loadingState: some View {
        if loading {
            ProgressView()
        } else {
            VStack(spacing: 6) {
                Text("Plans couldn't be loaded. Check your connection.")
                    .font(.footnote)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                Button("Retry") { Task { await reload(reportErrors: true) } }
                    .font(.footnote.weight(.semibold))
            }
        }
    }

    private var primaryButton: some View {
        Button {
            let plan = current
            run { await purchase.buy(plan) }
        } label: {
            Text(primaryButtonTitle)
                .font(.headline)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 6)
        }
        .buttonStyle(.borderedProminent)
        .tint(AppColors.info)
        .disabled(purchasingDisabled || purchase.product(for: current) == nil || inFlight)
    }

    private var primaryButtonTitle: String {
        if purchasingDisabled { return "You have Lifetime access" }
        return PaywallPricing.buttonTitle(for: current,
                                          trialText: purchase.trialText(for: current),
                                          lifetimePrice: purchase.displayPrice(for: .lifetime))
    }

    /// One row when it fits; stacked at large Dynamic Type sizes so nothing truncates.
    private var links: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 18) { linkItems }
            VStack(spacing: 10) { linkItems }
        }
        .font(.footnote)
        .tint(AppColors.info)
    }

    @ViewBuilder
    private var linkItems: some View {
        Button("Restore purchases") { run { await purchase.restore() } }
            .disabled(inFlight)
            .fixedSize()
        Link("Terms", destination: SettingsView.termsURL)
            .fixedSize()
        Link("Privacy", destination: SettingsView.privacyURL)
            .fixedSize()
    }

    // MARK: - Selection

    private var availablePlans: [PurchaseManager.Plan] {
        PurchaseManager.Plan.allCases.filter { purchase.product(for: $0) != nil }
    }

    private var currentPlan: PurchaseManager.Plan? { purchase.activePlan }

    private var purchasingDisabled: Bool { PaywallPricing.purchasingDisabled(currentPlan: currentPlan) }

    /// The plan the button acts on: never the current plan, see PaywallPricing.
    private var current: PurchaseManager.Plan {
        PaywallPricing.effectiveSelection(selected: selected, currentPlan: currentPlan, available: availablePlans)
    }

    // MARK: - Copy

    private func name(of plan: PurchaseManager.Plan) -> String {
        switch plan {
        case .yearly:   return "Yearly"
        case .monthly:  return "Monthly"
        case .lifetime: return "Lifetime"
        }
    }

    private func subtitle(of plan: PurchaseManager.Plan) -> String {
        switch plan {
        case .yearly, .monthly:
            let cadence = plan == .yearly ? "billed yearly" : "billed monthly"
            if let trial = purchase.trialText(for: plan) { return "\(trial.capitalizedFirst), then \(cadence)" }
            return cadence.capitalizedFirst
        case .lifetime:
            return "One-time purchase, no subscription"
        }
    }

    private func priceDetail(of plan: PurchaseManager.Plan) -> String? {
        switch plan {
        // Approximate: the yearly price is billed once, this is only its per-month equivalent.
        case .yearly:   return purchase.perMonthText(for: .yearly).map { "≈ \($0) / month" }
        case .monthly:  return purchase.displayPrice(for: .monthly) == nil ? nil : "per month"
        case .lifetime: return purchase.displayPrice(for: .lifetime) == nil ? nil : "pay once"
        }
    }

    // Guideline 3.1.2: billed amount, auto-renewal, charge timing and how to cancel, for the selected plan.
    private var disclosure: String {
        let privacy = " Traffic stays on this device; DNS lookups go to your chosen resolver."
        // Nothing is for sale to a lifetime owner, so no billing terms to disclose.
        if purchasingDisabled { return "Lifetime access is already on this Apple Account." + privacy }
        let price = purchase.displayPrice(for: current)
        switch current {
        case .lifetime:
            var text = price.map { "Lifetime: \($0) once. " } ?? ""
            text += "One-time purchase. No subscription. Charged to your Apple Account at purchase."
            return text + privacy
        case .yearly, .monthly:
            let hasTrial = purchase.trialText(for: current) != nil
            var text = ""
            if let price {
                let period = purchase.periodText(for: current).map { "/\($0)" } ?? ""
                text += "\(name(of: current)): \(price)\(period)\(hasTrial ? " after the trial" : ""). "
            }
            text += "Auto-renews until cancelled. Charged to your Apple Account"
            text += hasTrial ? " when the trial ends." : " at purchase."
            text += " Cancel at least 24 hours before renewal in Settings > Apple Account > Subscriptions."
            return text + privacy
        }
    }

    // MARK: - Actions

    private func reload(reportErrors: Bool) async {
        guard !purchase.productsLoaded, !loading else { return }
        loading = true
        await purchase.loadProducts(reportErrors: reportErrors)
        loading = false
    }

    private func run(_ operation: @escaping () async -> Void) {
        guard !inFlight else { return }
        inFlight = true
        Task {
            await operation()
            inFlight = false
        }
    }
}

private extension String {
    var capitalizedFirst: String { prefix(1).uppercased() + dropFirst() }
}
