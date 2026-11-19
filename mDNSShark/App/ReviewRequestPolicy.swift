// mDNSShark/App/ReviewRequestPolicy.swift
import Foundation

/// Decides when the App Store rating prompt may be requested. Holds no UI and no platform types, so the view layer only calls StoreKit.
struct ReviewRequestPolicy {
    static let launchesNeeded = 5
    static let minimumDaysBetweenAsks = 120
    /// A scan counts as a success moment only when it found at least this many devices.
    static let minimumDevicesForSuccessfulScan = 2
    static let successfulScansNeeded = 3

    enum Key {
        static let launchCount = "review.launchCount"
        static let lastAskedDate = "review.lastAskedDate"
        static let lastAskedVersion = "review.lastAskedVersion"
        static let successfulScanCount = "review.successfulScanCount"
        #if DEBUG
        /// Debug builds only: skips the scan threshold so the flow can be tried in the Simulator.
        static let debugForce = "review.debugForce"
        #endif
    }

    private let defaults: UserDefaults
    private let appVersion: String

    init(defaults: UserDefaults = .standard,
         appVersion: String = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "") {
        self.defaults = defaults
        self.appVersion = appVersion
    }

    /// Call once per foreground launch; new users are not asked until `launchesNeeded` of them.
    func noteLaunch() {
        defaults.set(defaults.integer(forKey: Key.launchCount) + 1, forKey: Key.launchCount)
    }

    /// Call when a scan ends; only scans that found real devices count, and the count is lifetime, not per version.
    func noteSuccessfulScan(deviceCount: Int) {
        guard deviceCount >= Self.minimumDevicesForSuccessfulScan else { return }
        defaults.set(defaults.integer(forKey: Key.successfulScanCount) + 1, forKey: Key.successfulScanCount)
    }

    /// True only when nothing the system alert could interrupt is running and the scene is active.
    static func isQuiet(scanning: Bool, bluetoothScanning: Bool, readingDeviceInfo: Bool, tunnelActive: Bool,
                        capturing: Bool, gateInFlight: Bool, securityRefreshing: Bool, sceneActive: Bool) -> Bool {
        sceneActive && !(scanning || bluetoothScanning || readingDeviceInfo || tunnelActive
                         || capturing || gateInFlight || securityRefreshing)
    }

    /// The launch and throttle rules alone, recording nothing; a last ask dated in the future (clock rolled back) also blocks.
    func isDue(now: Date = Date()) -> Bool {
        guard defaults.integer(forKey: Key.launchCount) >= Self.launchesNeeded else { return false }
        guard defaults.string(forKey: Key.lastAskedVersion) != appVersion else { return false }
        if let last = defaults.object(forKey: Key.lastAskedDate) as? Date,
           now.timeIntervalSince(last) < TimeInterval(Self.minimumDaysBetweenAsks) * 86_400 {
            return false
        }
        return true
    }

    /// `isDue` plus enough successful scans: the rule for asking right after a scan finishes.
    func isDueAfterScan(now: Date = Date()) -> Bool {
        guard isDue(now: now) else { return false }
        #if DEBUG
        if defaults.bool(forKey: Key.debugForce) { return true }
        #endif
        return defaults.integer(forKey: Key.successfulScanCount) >= Self.successfulScansNeeded
    }

    /// True when a prompt may be requested now; a true result is recorded as this version's ask.
    func consumeRequest(isQuiet: Bool, now: Date = Date()) -> Bool {
        guard isQuiet, isDue(now: now) else { return false }
        recordAsk(now: now)
        return true
    }

    /// Like `consumeRequest`, for the post-scan trigger, which also needs `successfulScansNeeded` good scans.
    func consumeScanRequest(isQuiet: Bool, now: Date = Date()) -> Bool {
        guard isQuiet, isDueAfterScan(now: now) else { return false }
        recordAsk(now: now)
        return true
    }

    private func recordAsk(now: Date) {
        defaults.set(now, forKey: Key.lastAskedDate)
        defaults.set(appVersion, forKey: Key.lastAskedVersion)
    }
}

/// Where "Could be better" and the About "Send feedback" row send people, so unhappy users have a direct path that is not a review.
enum ReviewPrompt {
    static let feedbackURL = URL(string: "https://github.com/Shapehaven-Innovations/mDNSShark/issues/new")!
}
