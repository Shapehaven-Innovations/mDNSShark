// mDNSShark/App/ContentView.swift
import SwiftUI

struct ContentView: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @AppStorage("preferredColorScheme") private var colorSchemeRaw: Int = 0
    @AppStorage("hasShownOnboarding")   private var hasShownOnboarding: Bool = false
    @State private var showBanner = false
    @State private var tlsError: String = ""

    private var preferredColorScheme: ColorScheme? {
        switch colorSchemeRaw { case 1: return .light; case 2: return .dark; default: return nil }
    }

    var body: some View {
        VStack(spacing: 0) {
            AppHeaderView()
            TabBarView(selectedTab: $coordinator.selectedTab)
            if showBanner {
                OnboardingBannerView(isVisible: $showBanner).padding(.top, 4)
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
        .preferredColorScheme(preferredColorScheme)
        .onAppear {
            if !hasShownOnboarding {
                withAnimation { showBanner = true }
                hasShownOnboarding = true
            }
            tlsError = SharedSettings.tlsInterceptorLastError
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
