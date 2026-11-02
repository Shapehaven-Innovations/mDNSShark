import Foundation

/// The entry dates and reload date a widget timeline uses for one snapshot.
public struct WidgetTimelinePlan: Equatable, Sendable {
    public struct Entry: Equatable, Sendable {
        public var date: Date
        public var isScanRunning: Bool

        public init(date: Date, isScanRunning: Bool) {
            self.date = date
            self.isScanRunning = isScanRunning
        }
    }

    public var entries: [Entry]
    public var reloadAfter: Date

    public init(entries: [Entry], reloadAfter: Date) {
        self.entries = entries
        self.reloadAfter = reloadAfter
    }

    static let missingReload: TimeInterval = 21_600
    static let day: TimeInterval = 86_400

    /// Entries carry minute precision for an hour so ages and the ring stay literal without a reload.
    public static func make(scannedAt: Date?, now: Date, awaitingUntil: Date?) -> WidgetTimelinePlan {
        var dates: [Date] = [now]
        let reloadAfter: Date
        if let scannedAt {
            if now >= scannedAt.addingTimeInterval(day) {
                let elapsedDays = Int(now.timeIntervalSince(scannedAt) / day)
                let boundaries = (1...3).map { scannedAt.addingTimeInterval(Double(elapsedDays + $0) * day) }
                dates += boundaries
                reloadAfter = boundaries[2]
            } else {
                let minutes = (1...60).map { scannedAt.addingTimeInterval(Double($0) * 60) }
                let hours = (2...23).map { scannedAt.addingTimeInterval(Double($0) * 3600) }
                dates += (minutes + hours).filter { $0 > now }
                reloadAfter = scannedAt.addingTimeInterval(day)
            }
        } else {
            reloadAfter = now.addingTimeInterval(missingReload)
        }
        let until = awaitingUntil.flatMap { $0 > now ? $0 : nil }
        if let until { dates.append(until) }
        let unique = Array(Set(dates)).sorted()
        let entries = unique.map { date in Entry(date: date, isScanRunning: until.map { date < $0 } ?? false) }
        return WidgetTimelinePlan(entries: entries, reloadAfter: reloadAfter)
    }
}
