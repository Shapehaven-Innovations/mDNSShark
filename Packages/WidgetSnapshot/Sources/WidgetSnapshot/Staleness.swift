import Foundation

public enum Staleness {
    public static let freshWindow: TimeInterval = 3600
    public static let newWindow: TimeInterval = 86_400

    public static func isFresh(scannedAt: Date, now: Date) -> Bool {
        now.timeIntervalSince(scannedAt) < freshWindow
    }

    /// 1 when just scanned, falling linearly to 0 at the fresh window; a future scan date counts as 1.
    public static func ringFraction(scannedAt: Date, now: Date) -> Double {
        let elapsed = max(0, now.timeIntervalSince(scannedAt))
        return max(0, min(1, 1 - elapsed / freshWindow))
    }

    public static func isNew(firstSeen: Date, now: Date) -> Bool {
        now.timeIntervalSince(firstSeen) < newWindow
    }
}
