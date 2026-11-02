import Foundation

/// A timestamped "scan now" request left by the widget intent and consumed once by the app.
public enum ScanRequestFlag {
    public static let key = "widgetScanRequested"
    public static let maxAge: TimeInterval = 120
    public static let didStamp = Notification.Name("ScanRequestFlag.didStamp")
    /// Never consumed, so the widget can show a running scan after the app takes the request.
    public static let lastRequestKey = "widgetScanLastRequested"

    public static func stamp(in defaults: UserDefaults, at date: Date) {
        defaults.set(date, forKey: key)
        defaults.set(date, forKey: lastRequestKey)
        NotificationCenter.default.post(name: didStamp, object: nil)
    }

    /// Shows the widget spinner for a scan the app is already running in the background; leaves no flag to consume.
    public static func markRunning(in defaults: UserDefaults, at date: Date) {
        defaults.set(date, forKey: lastRequestKey)
    }

    /// Hides the spinner when a background request could neither scan nor open the app; a stamped flag stays for the next launch.
    public static func clearRunning(in defaults: UserDefaults) {
        defaults.removeObject(forKey: lastRequestKey)
    }

    /// The time the widget stops showing a scan as running, or nil when no recent request is still waiting for a snapshot.
    public static func awaitingUntil(in defaults: UserDefaults, scannedAt: Date?, now: Date) -> Date? {
        guard let requested = defaults.object(forKey: lastRequestKey) as? Date else { return nil }
        let age = now.timeIntervalSince(requested)
        guard age >= 0, age <= maxAge else { return nil }
        if let scannedAt, scannedAt >= requested { return nil }
        return requested.addingTimeInterval(maxAge)
    }

    /// Always clears the key; true only for a request no older than `maxAge` and not dated in the future.
    public static func consume(from defaults: UserDefaults, now: Date) -> Bool {
        let stamped = defaults.object(forKey: key) as? Date
        defaults.removeObject(forKey: key)
        guard let stamped else { return false }
        let age = now.timeIntervalSince(stamped)
        return age >= 0 && age <= maxAge
    }
}
