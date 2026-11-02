import Foundation

extension StatusCounts {
    /// Warning plus critical.
    public var issues: Int { warning + critical }

    /// Needs at least one secure device; not probed devices do not block it, but pending ones do.
    public var isAllClear: Bool { issues == 0 && pending == 0 && secure > 0 }
}

public enum SnapshotFormatting {
    public static func age(since: Date, now: Date) -> String {
        let seconds = max(0, Int(now.timeIntervalSince(since)))
        func unit(_ n: Int, _ name: String) -> String { "\(n) \(name)\(n == 1 ? "" : "s") ago" }
        if seconds < 60 { return "just now" }
        if seconds < 3600 { return unit(seconds / 60, "minute") }
        if seconds < 86_400 { return unit(seconds / 3600, "hour") }
        return unit(seconds / 86_400, "day")
    }

    /// Abbreviated age for tight captions, such as "2 min ago".
    public static func shortAge(since: Date, now: Date) -> String {
        let seconds = max(0, Int(now.timeIntervalSince(since)))
        if seconds < 60 { return "just now" }
        if seconds < 3600 { return "\(seconds / 60) min ago" }
        if seconds < 86_400 { return "\(seconds / 3600) hr ago" }
        return "\(seconds / 86_400) d ago"
    }

    public static func issuePhrase(_ n: Int) -> String { "\(n) issue\(n == 1 ? "" : "s")" }

    /// The one VoiceOver label every Security widget shape uses.
    public static func securityAccessibilityLabel(counts: StatusCounts, scannedAt: Date, now: Date,
                                                  isStale: Bool, isScanRunning: Bool) -> String {
        let scanned = "scanned " + age(since: scannedAt, now: now)
        var body: String
        switch counts.securityVerdict {
        case .noDevices: body = "No devices found"
        case .issues(let n): body = "\(issuePhrase(n)): \(counts.critical) critical, \(counts.warning) warning"
        case .checking(let p): body = "0 issues, \(p) still being checked"
        case .allClear: body = WidgetCopy.allClear
        case .nothingProbed: body = "No device probed yet"
        }
        if counts.total > 0 {
            body += ". \(counts.secure) secure, \(counts.notProbed) not probed"
            if counts.pending > 0 { body += ", \(counts.pending) pending" }
        }
        body += ", " + scanned
        if isStale { body = WidgetCopy.outOfDate + ". " + body }
        return body + (isScanRunning ? WidgetCopy.scanRunningSuffix : "")
    }

    /// Compact age for the freshness ring center: minutes (0 while age reads "just now"), then hours, then days.
    public static func ringAge(since: Date, now: Date) -> (value: Int, unit: String) {
        let seconds = max(0, Int(now.timeIntervalSince(since)))
        if seconds < 3600 { return (seconds / 60, "min") }
        if seconds < 86_400 { return (seconds / 3600, "hr") }
        return (seconds / 86_400, "d")
    }

    /// 1000-based units; a value that rounds up to 1000 is shown in the next unit.
    public static func bytes(_ count: Int64) -> String {
        if count < 1000 { return "\(max(0, count)) B" }
        let steps: [(name: String, divisor: Double, decimals: Int)] = [("KB", 1e3, 0), ("MB", 1e6, 1), ("GB", 1e9, 1)]
        func format(_ step: (name: String, divisor: Double, decimals: Int)) -> (text: String, value: Double) {
            let scale = pow(10.0, Double(step.decimals))
            let rounded = (Double(count) / step.divisor * scale).rounded() / scale
            let text = step.decimals == 0 ? "\(Int(rounded)) \(step.name)" : String(format: "%.1f %@", rounded, step.name)
            return (text, rounded)
        }
        for step in steps.dropLast() {
            let result = format(step)
            if result.value < 1000 { return result.text }
        }
        return format(steps[steps.count - 1]).text
    }

    /// Largest remainder method over positive finite shares; ties go to the smaller key.
    public static func wholePercents(_ shares: [String: Double]) -> [String: Int] {
        let valid = shares.filter { $0.value > 0 && $0.value.isFinite }
        let sum = valid.values.reduce(0, +)
        guard sum > 0 else { return [:] }
        var result: [String: Int] = [:]
        var remainders: [(key: String, fraction: Double)] = []
        for (key, value) in valid {
            let exact = value / sum * 100
            let floored = exact.rounded(.down)
            result[key] = Int(floored)
            remainders.append((key, exact - floored))
        }
        var leftover = 100 - result.values.reduce(0, +)
        for item in remainders.sorted(by: { $0.fraction != $1.fraction ? $0.fraction > $1.fraction : $0.key < $1.key }) {
            if leftover <= 0 { break }
            result[item.key, default: 0] += 1
            leftover -= 1
        }
        return result
    }

    /// Secure through not probed always, pending only when above zero.
    public static func statusPhrases(_ counts: StatusCounts) -> [String] {
        var parts = ["\(counts.secure) secure", "\(counts.warning) warning", "\(counts.critical) critical",
                     "\(counts.notProbed) not probed"]
        if counts.pending > 0 { parts.append("\(counts.pending) pending") }
        return parts
    }

    public static func accessibilityLabel(counts: StatusCounts, scannedAt: Date, now: Date) -> String {
        var parts = ["\(counts.total) device\(counts.total == 1 ? "" : "s")"] + statusPhrases(counts)
        parts.append("scanned " + age(since: scannedAt, now: now))
        return parts.joined(separator: ", ")
    }
}
