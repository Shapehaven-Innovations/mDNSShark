// mDNSShark/Settings/PaywallView.swift
// Three-plan TLS Inspection paywall sheet, opened from the Packets tab and Settings.
// Every price shown comes from StoreKit via PurchaseManager, never hard-coded.
import SwiftUI

struct PaywallView: View {
    @ObservedObject var purchase: PurchaseManager
    @Environment(\.dismiss) private var dismiss
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    /// The user's explicit pick; nil until they tap a row, so the preselection can
    /// follow the current plan once StoreKit reports it.
    @State private var selected: PurchaseManager.Plan?
    @State private var inFlight = false
    @State private var loading = false

    // Vertical rhythm, scaled with Dynamic Type so the gaps grow with the text.
    /// Clears the grab handle and the close button (12pt inset + ~28pt glyph).
    @ScaledMetric(relativeTo: .title2) private var topInset: CGFloat = 56
    /// Header and feature list read as one group, so their gap stays close to the
    /// gap between plan rows.
    @ScaledMetric(relativeTo: .body) private var headerGap: CGFloat = 18
    /// Gap between the feature list and the plans; grows with spare height up to the max.
    @ScaledMetric(relativeTo: .body) private var sectionGap: CGFloat = 24
    @ScaledMetric(relativeTo: .body) private var sectionGapMax: CGFloat = 48
    /// Gap inside a section: between plan rows and between the footer's lines.
    @ScaledMetric(relativeTo: .body) private var itemGap: CGFloat = 12
    @ScaledMetric(relativeTo: .body) private var rowVerticalPadding: CGFloat = 12
    /// How far a badge overhangs its row's top edge; the row gets that much extra
    /// room above it so the badge never crowds the row before.
    @ScaledMetric(relativeTo: .caption2) private var badgeOverhang: CGFloat = 9

    init(purchase: PurchaseManager) {
        self.purchase = purchase
    }

    var body: some View {
        // Header, features and plans scroll; the offer line, button and links are
        // pinned in a bottom inset so they never fall below the fold (iPhone SE,
        // large text). At accessibility sizes the long fine print would make the
        // pinned footer taller than half the screen, so it scrolls with the content.
        GeometryReader { sheet in
            let finePrintScrolls = finePrintScrolls(sheetHeight: sheet.size.height)
            GeometryReader { scrollArea in
                ScrollView(showsIndicators: true) {
                    VStack(spacing: 0) {
                        header
                        features
                            .padding(.top, headerGap)
                        Spacer(minLength: sectionGap)
                            .frame(maxHeight: sectionGapMax)
                        plans
                        if availablePlans.isEmpty {
                            loadingState
                                .padding(.top, itemGap)
                        }
                        if finePrintScrolls {
                            finePrint
                                .padding(.top, sectionGap)
                        }
                    }
                    .padding(.horizontal, 20)
                    .padding(.top, topInset)
                    .padding(.bottom, sectionGap)
                    // Fill the area above the footer so the flexible gap can spread
                    // short content; taller content simply scrolls.
                    .frame(minHeight: scrollArea.size.height
                           - scrollArea.safeAreaInsets.top - scrollArea.safeAreaInsets.bottom)
                }
            }
            .safeAreaInset(edge: .bottom, spacing: 0) { footer(finePrintScrolls: finePrintScrolls) }
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

    // MARK: - Scrolling content

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
            feature("Pay monthly, yearly, or once")
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
                Group {
                    if plan == currentPlan {
                        currentPlanRow(plan)
                    } else {
                        planRow(plan)
                    }
                }
                .padding(.top, badge(for: plan) == nil ? 0 : badgeOverhang)
            }
        }
        .disabled(availablePlans.isEmpty || inFlight)
    }

    private func planRow(_ plan: PurchaseManager.Plan) -> some View {
        let isSelected = !purchasingDisabled && current == plan
        return Button { selected = plan } label: {
            planRowContent(plan, subtitle: subtitle(of: plan), emphasized: isSelected)
                .background(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(isSelected ? AppColors.info.opacity(0.12) : Color(.secondarySystemGroupedBackground))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .stroke(isSelected ? AppColors.info : Color(.separator), lineWidth: isSelected ? 2 : 1)
                )
                .overlay(alignment: .topLeading) {
                    if let badge = badge(for: plan) { badge }
                }
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(isSelected ? .isSelected : [])
        // A lifetime owner has nothing to pick: the other rows are shown for context only.
        .disabled(purchasingDisabled)
        .opacity(purchasingDisabled ? 0.45 : 1)
    }

    /// The plan the user is already on: not a button, clearly lower emphasis than the
    /// buyable rows in both appearances, marked so it still reads as one of the offers.
    private func currentPlanRow(_ plan: PurchaseManager.Plan) -> some View {
        planRowContent(plan, subtitle: currentPlanSubtitle(for: plan), emphasized: false)
            .background(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(Color(.secondarySystemGroupedBackground).opacity(0.5))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .strokeBorder(style: StrokeStyle(lineWidth: 1, dash: [5, 4]))
                    .foregroundColor(Color(.secondaryLabel).opacity(0.5))
            )
            .overlay(alignment: .topLeading) {
                if let badge = badge(for: plan) { badge }
            }
            .accessibilityElement(children: .combine)
            .accessibilityValue("Current plan")
    }

    /// Name, subtitle and price block side by side; stacked full-width at
    /// accessibility sizes so neither column wraps word by word.
    @ViewBuilder
    private func planRowContent(_ plan: PurchaseManager.Plan, subtitle: String?, emphasized: Bool) -> some View {
        let secondary: Color = emphasized ? Color.primary.opacity(0.7) : .secondary
        Group {
            if dynamicTypeSize.isAccessibilitySize {
                VStack(alignment: .leading, spacing: 4) {
                    Text(PaywallPricing.name(of: plan)).font(.headline)
                    // Guideline 3.1.2(c): the billed amount outranks any trial wording.
                    if let price = purchase.displayPrice(for: plan) {
                        Text(price).font(.title3.weight(.bold))
                    }
                    if let subtitle {
                        Text(subtitle).font(.caption).foregroundColor(secondary)
                    }
                    if plan == .yearly, let detail = priceDetail(of: plan) {
                        Text(detail).font(.caption).foregroundColor(secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                HStack(alignment: .center, spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(PaywallPricing.name(of: plan)).font(.headline)
                        if let subtitle {
                            Text(subtitle).font(.caption).foregroundColor(secondary)
                        }
                    }
                    Spacer(minLength: 8)
                    VStack(alignment: .trailing, spacing: 2) {
                        if let price = purchase.displayPrice(for: plan) {
                            Text(price).font(.title3.weight(.bold))
                        }
                        if let detail = priceDetail(of: plan) {
                            Text(detail)
                                .font(.caption)
                                .foregroundColor(secondary)
                                .lineLimit(1)
                                .fixedSize()
                        }
                    }
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, rowVerticalPadding)
        .frame(maxWidth: .infinity)
    }

    /// Best value on the default plan while it is for sale; the current plan marker
    /// otherwise. A lifetime owner sees no best-value badge at all.
    private func badge(for plan: PurchaseManager.Plan) -> AnyView? {
        if plan == currentPlan {
            return AnyView(badge("CURRENT PLAN", fill: Color(.label).opacity(0.7), text: Color(.systemBackground)))
        }
        if plan == PaywallPricing.defaultPlan, !purchasingDisabled {
            return AnyView(badge("BEST VALUE", fill: AppColors.secure, text: .black))
        }
        return nil
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

    // MARK: - Pinned footer

    /// The offer line, button and links stay pinned at every size. The fine print
    /// scrolls with the content once pinning it would take about half the sheet:
    /// at accessibility sizes, and at large sizes on screens too short for it.
    private func finePrintScrolls(sheetHeight: CGFloat) -> Bool {
        dynamicTypeSize.isAccessibilitySize
            || (dynamicTypeSize >= .xLarge && sheetHeight < 700)
            || (dynamicTypeSize >= .xxLarge && sheetHeight < 900)
    }

    private func footer(finePrintScrolls: Bool) -> some View {
        VStack(spacing: itemGap) {
            if let offer = offerLine {
                Text(offer)
                    .font(.headline)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            primaryButton
            if !finePrintScrolls {
                finePrint
            }
            links
        }
        .padding(.horizontal, 20)
        .padding(.top, itemGap)
        .padding(.bottom, 8)
        .frame(maxWidth: .infinity)
        .background(Color(.systemGroupedBackground))
        .overlay(alignment: .top) { Divider() }
    }

    /// Billing disclosure (guideline 3.1.2) and, on its own line, the privacy note.
    private var finePrint: some View {
        VStack(spacing: 6) {
            Text(disclosure)
            Text("Traffic stays on this device; DNS lookups go to your chosen resolver.")
        }
        .font(.caption)
        .foregroundColor(.secondary)
        .multilineTextAlignment(.center)
        .fixedSize(horizontal: false, vertical: true)
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

    // MARK: - Copy (all composed in PaywallPricing from store strings)

    /// Store trial wording, gated so nobody already on a plan ever sees it.
    private func trialText(for plan: PurchaseManager.Plan) -> String? {
        PaywallPricing.trialText(purchase.trialText(for: plan), currentPlan: currentPlan)
    }

    private func billed(for plan: PurchaseManager.Plan) -> String? {
        PaywallPricing.billedText(price: purchase.displayPrice(for: plan), period: purchase.periodText(for: plan))
    }

    private func subtitle(of plan: PurchaseManager.Plan) -> String? {
        PaywallPricing.rowSubtitle(for: plan, trialText: trialText(for: plan), billed: billed(for: plan),
                                   lifetimePrice: purchase.displayPrice(for: .lifetime))
    }

    private func currentPlanSubtitle(for plan: PurchaseManager.Plan) -> String? {
        plan == .lifetime ? nil : PaywallPricing.currentPlanSubtitle(state: purchase.subscriptionState)
    }

    private func priceDetail(of plan: PurchaseManager.Plan) -> String? {
        switch plan {
        // Approximate: the yearly price is billed once, this is only its per-month equivalent.
        case .yearly:   return purchase.perMonthText(for: .yearly).map { "≈ \($0) per month" }
        case .monthly:  return purchase.displayPrice(for: .monthly) == nil ? nil : "per month"
        case .lifetime: return purchase.displayPrice(for: .lifetime) == nil ? nil : "pay once"
        }
    }

    private var offerLine: String? {
        PaywallPricing.offerLine(for: current, currentPlan: currentPlan, trialText: trialText(for: current),
                                 billed: billed(for: current), lifetimePrice: purchase.displayPrice(for: .lifetime))
    }

    private var primaryButtonTitle: String {
        PaywallPricing.buttonTitle(for: current, currentPlan: currentPlan, trialText: trialText(for: current),
                                   lifetimePrice: purchase.displayPrice(for: .lifetime))
    }

    private var disclosure: String {
        PaywallPricing.disclosure(for: current, currentPlan: currentPlan, trialText: trialText(for: current),
                                  billed: billed(for: current), lifetimePrice: purchase.displayPrice(for: .lifetime))
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
