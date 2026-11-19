// mDNSShark/App/ContentView.swift
import SwiftUI
import StoreKit
import WidgetSnapshot

struct ContentView: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @EnvironmentObject var scanVM: NetworkScanViewModel
    @AppStorage("hasShownOnboarding")   private var hasShownOnboarding: Bool = false
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.requestReview) private var requestReview
    @State private var showBanner = false
    @State private var showSplash = !UIAccessibility.isVoiceOverRunning
    @State private var tlsError: String = ""
    @State private var launchCounted = false
    @State private var showEnjoyingPrompt = false

    var body: some View {
        VStack(spacing: 0) {
            AppHeaderView()
            TabBarView(selectedTab: $coordinator.selectedTab)
            if showBanner {
                OnboardingBannerView(isVisible: $showBanner).padding(.top, 4)
            }
            if scanVM.isLocalNetworkDenied {
                LocalNetworkDeniedBanner().padding(.horizontal, 16).padding(.top, 4)
            }
            if !tlsError.isEmpty {
                TLSErrorBanner(message: tlsError, onDismiss: {
                    SharedSettings.tlsInterceptorLastError = ""
                    tlsError = ""
                })
                .padding(.horizontal, 16).padding(.top, 4)
            }
            tabContent.frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .accessibilityHidden(showSplash)
        .overlay {
            if showSplash {
                SplashView {
                    showSplash = false
                    showOnboardingIfNeeded()
                }
            }
        }
        // The one trigger for the Local Network alert: splash gone and app active. It re-fires on every return to the foreground until granted, so the alert is never lost.
        .onChange(of: scenePhase == .active && !showSplash, initial: true) { _, ready in
            if ready {
                // One count per foreground launch, for the rating prompt's new-user threshold.
                if !launchCounted {
                    launchCounted = true
                    ReviewRequestPolicy().noteLaunch()
                }
                scanVM.startLaunchGateIfNeeded(isActive: true)
                coordinator.consumeWidgetScanRequest()
            }
        }
        // Covers the widget intent running after the app is already active.
        .onReceive(NotificationCenter.default.publisher(for: ScanRequestFlag.didStamp).receive(on: DispatchQueue.main)) { _ in
            if scenePhase == .active && !showSplash { coordinator.consumeWidgetScanRequest() }
        }
        // The coordinator's own scanFinished sink has already counted this scan; the check below re-reads that count.
        .onReceive(scanVM.scanFinished.receive(on: DispatchQueue.main)) { _ in
            Task { await requestReviewAfterScanIfAllowed() }
        }
        .alert("Enjoying mDNSShark?", isPresented: $showEnjoyingPrompt) {
            Button("Yes") { requestReview() }
            Button("Could be better") { UIApplication.shared.open(ReviewPrompt.feedbackURL) }
            Button("Not now", role: .cancel) {}
        } message: {
            Text("Your feedback helps us improve it.")
        }
        .onOpenURL { coordinator.open($0) }
        .onChange(of: scenePhase) { _, phase in
            coordinator.bluetoothViewModel.scenePhaseChanged(isActive: phase == .active)
            if phase == .active {
                Task { await PurchaseManager.shared.refreshEntitlements() }
                let reason = SharedSettings.tlsInterceptorLastError
                tlsError = SharedSettings.userFacingTLSDropMessage(reason) ?? ""
            }
        }
        .onAppear {
            // With no splash (VoiceOver) the banner shows right away instead of after the splash.
            if !showSplash { showOnboardingIfNeeded() }
            let reason = SharedSettings.tlsInterceptorLastError
            tlsError = SharedSettings.userFacingTLSDropMessage(reason) ?? ""
        }
    }

    private var canAskForReview: Bool {
        scenePhase == .active && !showSplash && !showBanner && !scanVM.isLocalNetworkDenied
    }

    /// Asks right after a scan that found devices, once enough good scans have passed; `ReviewRequestPolicy` holds the rules.
    private func requestReviewAfterScanIfAllowed() async {
        let policy = ReviewRequestPolicy()
        guard policy.isDueAfterScan(), canAskForReview else { return }
        // Let the results settle before asking.
        try? await Task.sleep(for: .seconds(1.5))
        guard !Task.isCancelled, canAskForReview else { return }
        let isQuiet = await coordinator.reviewQuietFlags()
        guard policy.consumeScanRequest(isQuiet: isQuiet) else { return }
        showEnjoyingPrompt = true
    }

    private func showOnboardingIfNeeded() {
        guard !hasShownOnboarding else { return }
        withAnimation { showBanner = true }
        hasShownOnboarding = true
    }

    @ViewBuilder
    private var tabContent: some View {
        switch coordinator.selectedTab {
        case .topology: TopologyView()
        case .devices:  DevicesView()
        case .security: SecurityView()
        case .packets:  PacketCaptureView()
        case .analysis: AnalysisView()
        case .settings: SettingsView()
        }
    }
}

private struct LocalNetworkDeniedBanner: View {
    var body: some View {
        HStack {
            Image(systemName: "wifi.exclamationmark").foregroundColor(AppColors.warning)
            Text("Local Network access is off, so scans can only find your router. Turn it on in Settings.")
                .font(.caption).foregroundColor(.primary)
            Spacer()
            Button("Open Settings") {
                if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
            }
            .font(.caption)
        }
        .padding(10)
        .background(AppColors.warning.opacity(0.15))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

private struct TLSErrorBanner: View {
    let message: String
    let onDismiss: () -> Void
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.shield.fill").foregroundColor(AppColors.warning)
            Text(message).font(.caption).foregroundColor(.primary)
            Spacer()
            Button("Dismiss", action: onDismiss).font(.caption)
        }
        .padding(10)
        .background(AppColors.warning.opacity(0.15))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}
