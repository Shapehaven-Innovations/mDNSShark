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

    /// Entries carry minute precision for an hour so ages and the ring stay literal without a reload; a Bluetooth scan adds its own marks.
    public static func make(scannedAt: Date?, now: Date, awaitingUntil: Date?,
                            bluetoothScannedAt: Date? = nil) -> WidgetTimelinePlan {
        var dates: [Date] = [now]
        var anchors: [Date] = []
        var reloadAfter: Date
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
        if let bt = bluetoothScannedAt {
            let minutes = (1...30).map { bt.addingTimeInterval(Double($0) * 60) }
            let hours = (1...23).map { bt.addingTimeInterval(Double($0) * 3600) }
            let omit = bt.addingTimeInterval(day)
            dates += (minutes + hours + [omit]).filter { $0 > now }
            anchors += [bt.addingTimeInterval(Staleness.bluetoothFreshWindow), omit].filter { $0 > now }
            if omit > now { reloadAfter = min(reloadAfter, omit) }
        }
        let until = awaitingUntil.flatMap { $0 > now ? $0 : nil }
        if let until { dates.append(until) }
        let unique = spaced(Array(Set(dates)).sorted(), keeping: Set([now] + (until.map { [$0] } ?? [])), anchors: Set(anchors))
        let entries = unique.map { date in Entry(date: date, isScanRunning: until.map { date < $0 } ?? false) }
        return WidgetTimelinePlan(entries: entries, reloadAfter: reloadAfter)
    }

    static let minimumGap: TimeInterval = 60

    /// Drops any date less than a minute before the next kept one, keeping the later. `now` and the scan timeout always
    /// stay as they did before Bluetooth; the Bluetooth stale and omit boundaries also stay and displace an ordinary mark under a minute after them.
    static func spaced(_ sorted: [Date], keeping fixed: Set<Date>, anchors: Set<Date>) -> [Date] {
        var kept: [Date] = []
        for date in sorted.reversed() {
            if fixed.contains(date) {
                // Kept without displacing anything, as before.
            } else if anchors.contains(date) {
                while let next = kept.last, !fixed.contains(next), !anchors.contains(next),
                      next.timeIntervalSince(date) < minimumGap { kept.removeLast() }
            } else if let next = kept.last, next.timeIntervalSince(date) < minimumGap {
                continue
            }
            kept.append(date)
        }
        return kept.reversed()
    }
}
