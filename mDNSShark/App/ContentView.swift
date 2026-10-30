// mDNSShark/App/ContentView.swift
import SwiftUI

struct ContentView: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @AppStorage("hasShownOnboarding")   private var hasShownOnboarding: Bool = false
    @Environment(\.scenePhase) private var scenePhase
    @State private var showBanner = false
    @State private var tlsError: String = ""

    var body: some View {
        VStack(spacing: 0) {
            AppHeaderView()
            TabBarView(selectedTab: $coordinator.selectedTab)
            if showBanner {
                OnboardingBannerView(isVisible: $showBanner).padding(.top, 4)
            }
            if coordinator.networkScanViewModel.isLocalNetworkDenied {
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
        .onChange(of: scenePhase) { _, phase in
            if phase == .active {
                Task { await PurchaseManager.shared.refreshEntitlements() }
                let reason = SharedSettings.tlsInterceptorLastError
                tlsError = SharedSettings.userFacingTLSDropMessage(reason) ?? ""
            }
        }
        .onAppear {
            if !hasShownOnboarding {
                withAnimation { showBanner = true }
                hasShownOnboarding = true
            }
            let reason = SharedSettings.tlsInterceptorLastError
            tlsError = SharedSettings.userFacingTLSDropMessage(reason) ?? ""
        }
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
