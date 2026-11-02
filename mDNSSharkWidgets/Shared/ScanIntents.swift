import AppIntents
import Foundation
import WidgetKit
import WidgetSnapshot

/// Picks the widget Scan button's intent: true runs the scan in the app process without opening it (iOS 26+), false keeps ScanNowIntent.
enum WidgetScanIntentChoice {
    static let runsInBackground = true
}

/// Public so the Release build can look the intent up by identifier, like BackgroundScanIntent.
public struct ScanNowIntent: AppIntent {
    public static let title: LocalizedStringResource = "Scan Now"
    public static let description = IntentDescription("Opens mDNSShark and scans your network.")
    public static let openAppWhenRun: Bool = true

    public init() {}

    // Scanning stays in the app process; the intent only leaves a flag.
    public func perform() async throws -> some IntentResult {
        ScanRequestFlag.stamp(in: UserDefaults(suiteName: AppGroup.identifier) ?? .standard, at: Date())
        for kind in [WidgetKind.devices, WidgetKind.scan, WidgetKind.security] {
            WidgetCenter.shared.reloadTimelines(ofKind: kind)
        }
        return .result()
    }
}

/// Implemented by the app only; the widget extension never registers one, so it can never scan.
@MainActor
protocol WidgetScanPerforming: AnyObject {
    func performWidgetScan(openApp: @escaping @MainActor () async -> Bool) async
}

@MainActor
enum WidgetScanHandoff {
    static weak var performer: (any WidgetScanPerforming)?
}

/// LiveActivityIntent makes the system run perform() in the app process, launching it in the background if needed.
public struct BackgroundScanIntent: LiveActivityIntent {
    public static let title: LocalizedStringResource = "Scan Network in Background"
    public static let description = IntentDescription("Scans your network without opening mDNSShark and refreshes its widgets.")
    public static let openAppWhenRun: Bool = false
    public static let isDiscoverable: Bool = false

    @available(iOS 26.0, *)
    public static var supportedModes: IntentModes { [.background, .foreground(.dynamic)] }

    public init() {}

    public func perform() async throws -> some IntentResult {
        if let performer = await WidgetScanHandoff.performer {
            await performer.performWidgetScan { await self.openAppIfPossible() }
        } else {
            // Only reached if the system ran this in the widget extension: leave the flag, exactly like ScanNowIntent.
            ScanRequestFlag.stamp(in: UserDefaults(suiteName: AppGroup.identifier) ?? .standard, at: Date())
        }
        return .result()
    }

    /// Brings the app forward for the permission flow; false when the system does not allow it from this run.
    @MainActor
    private func openAppIfPossible() async -> Bool {
        guard #available(iOS 26.0, *) else { return false }
        guard systemContext.currentMode.canContinueInForeground else { return false }
        do {
            try await continueInForeground(nil, alwaysConfirm: false)
            return true
        } catch {
            return false
        }
    }
}
