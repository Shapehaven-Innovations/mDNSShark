// mDNSShark/App/ContentView.swift
import SwiftUI

struct ContentView: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @EnvironmentObject var scanVM: NetworkScanViewModel
    @AppStorage("hasShownOnboarding")   private var hasShownOnboarding: Bool = false
    @Environment(\.scenePhase) private var scenePhase
    @State private var showBanner = false
    @State private var showSplash = !UIAccessibility.isVoiceOverRunning
    @State private var tlsError: String = ""

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
            if ready { scanVM.startLaunchGateIfNeeded(isActive: true) }
        }
        .onChange(of: scenePhase) { _, phase in
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
