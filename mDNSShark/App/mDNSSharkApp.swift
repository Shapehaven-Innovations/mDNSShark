// mDNSShark/App/mDNSSharkApp.swift
import SwiftUI

@main
struct mDNSSharkApp: App {
    @StateObject private var coordinator: AppCoordinator

    // Built here, not lazily by the scene, so a widget scan intent that launches the app in the background finds it.
    init() {
        let coordinator = AppCoordinator()
        _coordinator = StateObject(wrappedValue: coordinator)
        WidgetScanHandoff.performer = coordinator
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(coordinator)
                // Each child is injected on its own so a view re-renders only for the objects it reads; the coordinator publishes just the tab.
                .environmentObject(coordinator.networkScanViewModel)
                .environmentObject(coordinator.securityViewModel)
                .environmentObject(coordinator.packetCaptureManager)
                .environmentObject(coordinator.analysisViewModel)
                .environmentObject(coordinator.deepLinkRouter)
                .environmentObject(coordinator.bluetoothViewModel)
        }
    }
}
