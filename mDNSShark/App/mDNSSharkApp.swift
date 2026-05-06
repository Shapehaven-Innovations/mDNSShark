// mDNSShark/App/mDNSSharkApp.swift
import SwiftUI

@main
struct mDNSSharkApp: App {
    @StateObject private var coordinator = AppCoordinator()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(coordinator)
        }
    }
}
