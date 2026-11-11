// mDNSShark/App/ReviewRequestPolicy.swift
import Foundation

/// Decides when the App Store rating prompt may be requested. Holds no UI and no platform types, so the view layer only calls StoreKit.
struct ReviewRequestPolicy {
    static let launchesNeeded = 5
    static let minimumDaysBetweenAsks = 120

    enum Key {
        static let launchCount = "review.launchCount"
        static let lastAskedDate = "review.lastAskedDate"
        static let lastAskedVersion = "review.lastAskedVersion"
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

    /// True when a prompt may be requested now; a true result is recorded as this version's ask.
    func consumeRequest(isQuiet: Bool, now: Date = Date()) -> Bool {
        guard isQuiet, isDue(now: now) else { return false }
        defaults.set(now, forKey: Key.lastAskedDate)
        defaults.set(appVersion, forKey: Key.lastAskedVersion)
        return true
    }
}
