// mDNSShark/App/mDNSSharkApp.swift
import SwiftUI

@main
struct mDNSSharkApp: App {
    @StateObject private var coordinator = AppCoordinator()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(coordinator)
                // Each child is injected on its own so a view re-renders only for the objects it reads; the coordinator publishes just the tab.
                .environmentObject(coordinator.networkScanViewModel)
                .environmentObject(coordinator.securityViewModel)
                .environmentObject(coordinator.packetCaptureManager)
                .environmentObject(coordinator.analysisViewModel)
        }
    }
}
