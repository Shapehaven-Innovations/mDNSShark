// mDNSShark/App/ContentView.swift
import SwiftUI

struct ContentView: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @AppStorage("preferredColorScheme") private var colorSchemeRaw: Int = 0
    @AppStorage("hasShownOnboarding")   private var hasShownOnboarding: Bool = false
    @State private var showBanner = false

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
            tabContent.frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .preferredColorScheme(preferredColorScheme)
        .onAppear {
            if !hasShownOnboarding {
                withAnimation { showBanner = true }
                hasShownOnboarding = true
            }
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
        }
    }
}
