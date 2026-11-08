import Foundation

public enum BLEMatchTier: Int, Comparable, Sendable {
    case none = 0, possible = 1, strong = 2
    public static func < (a: BLEMatchTier, b: BLEMatchTier) -> Bool { a.rawValue < b.rawValue }
}

/// A LAN device as the matcher sees it.
public struct BLEMatchCandidate: Equatable, Sendable, Identifiable {
    public var id: UUID
    public var name: String
    public var manufacturer: String?
    public var matterVendorID: UInt16?
    public var matterProductID: UInt16?
    public var hasAirPlay: Bool
    public var hasHomeKit: Bool

    public init(id: UUID, name: String, manufacturer: String?, matterVendorID: UInt16?, matterProductID: UInt16?,
                hasAirPlay: Bool, hasHomeKit: Bool) {
        self.id = id; self.name = name; self.manufacturer = manufacturer
        self.matterVendorID = matterVendorID; self.matterProductID = matterProductID
        self.hasAirPlay = hasAirPlay; self.hasHomeKit = hasHomeKit
    }
}

/// A Bluetooth peripheral as the matcher sees it.
public struct BLEMatchSubject: Equatable, Sendable, Identifiable {
    public var id: UUID
    public var name: String?
    public var companyName: String?
    public var matterVendorID: UInt16?
    public var matterProductID: UInt16?
    public var continuity: Set<AppleContinuityType>
    public var homeKitCategory: Int?

    public init(id: UUID, name: String?, companyName: String?, matterVendorID: UInt16?, matterProductID: UInt16?,
                continuity: Set<AppleContinuityType>, homeKitCategory: Int?) {
        self.id = id; self.name = name; self.companyName = companyName
        self.matterVendorID = matterVendorID; self.matterProductID = matterProductID
        self.continuity = continuity; self.homeKitCategory = homeKitCategory
    }
}

public struct BLEMatchReason: Equatable, Sendable {
    public var tier: BLEMatchTier
    public var caption: String
    public init(tier: BLEMatchTier, caption: String) { self.tier = tier; self.caption = caption }
}

public struct BLESuggestion: Equatable, Sendable {
    public var peripheralID: UUID
    public var deviceID: UUID
    public var tier: BLEMatchTier
    public var caption: String
    public init(peripheralID: UUID, deviceID: UUID, tier: BLEMatchTier, caption: String) {
        self.peripheralID = peripheralID; self.deviceID = deviceID; self.tier = tier; self.caption = caption
    }
}

public struct BLETie: Equatable, Sendable {
    public var peripheralID: UUID
    /// Sorted by uuidString.
    public var deviceIDs: [UUID]
    public var tier: BLEMatchTier
    public init(peripheralID: UUID, deviceIDs: [UUID], tier: BLEMatchTier) {
        self.peripheralID = peripheralID; self.deviceIDs = deviceIDs; self.tier = tier
    }
}

public struct BLEMatchTable: Equatable, Sendable {
    public var suggestions: [BLESuggestion]
    public var ties: [BLETie]

    public init(suggestions: [BLESuggestion], ties: [BLETie]) { self.suggestions = suggestions; self.ties = ties }

    public static let empty = BLEMatchTable(suggestions: [], ties: [])

    public func suggestions(forDevice id: UUID) -> [BLESuggestion] { suggestions.filter { $0.deviceID == id } }
    public func suggestion(forPeripheral id: UUID) -> BLESuggestion? { suggestions.first { $0.peripheralID == id } }
    public func tie(forPeripheral id: UUID) -> BLETie? { ties.first { $0.peripheralID == id } }
    public func ties(forDevice id: UUID) -> [BLETie] { ties.filter { $0.deviceIDs.contains(id) } }
    public var suggestedDeviceIDs: Set<UUID> { Set(suggestions.map(\.deviceID)) }
    public var suggestedPeripheralIDs: Set<UUID> { Set(suggestions.map(\.peripheralID)) }
}

/// Scores Bluetooth peripherals against LAN devices. Every result is an inference, never a confirmation.
public enum BLEMatcher {
    /// Only an AirPlay receiver message fits an AirPlay host; phones, tablets and Macs send Handoff and Nearby Info all the time.
    private static let continuityFits: Set<AppleContinuityType> = [.airPlayTarget]

    public static func score(_ subject: BLEMatchSubject, _ candidate: BLEMatchCandidate) -> BLEMatchReason {
        if let sv = subject.matterVendorID, let sp = subject.matterProductID,
           sv == candidate.matterVendorID, sp == candidate.matterProductID {
            return BLEMatchReason(tier: .strong, caption: "Inferred, not confirmed: Matter vendor and product IDs match.")
        }
        guard vendorsAgree(subject.companyName, candidate.manufacturer) else {
            return BLEMatchReason(tier: .none, caption: "")
        }
        if let name = subject.name {
            let a = normalizedName(name)
            if !a.isEmpty, a == normalizedName(candidate.name) {
                return BLEMatchReason(tier: .strong, caption: "Inferred, not confirmed: same name, same vendor.")
            }
            if namesSimilar(name, candidate.name) {
                return BLEMatchReason(tier: .possible, caption: "Inferred: similar name, same vendor.")
            }
        }
        if candidate.hasAirPlay, !subject.continuity.isDisjoint(with: continuityFits) {
            return BLEMatchReason(tier: .possible, caption: "Inferred: same vendor, Apple Continuity fits this host.")
        }
        if candidate.hasHomeKit, subject.homeKitCategory != nil {
            return BLEMatchReason(tier: .possible, caption: "Inferred: same vendor, HomeKit accessory fits this host.")
        }
        return BLEMatchReason(tier: .none, caption: "")
    }

    public static func match(subjects: [BLEMatchSubject], candidates: [BLEMatchCandidate]) -> BLEMatchTable {
        var suggestions: [BLESuggestion] = []
        var ties: [BLETie] = []
        for subject in subjects {
            let scored = candidates.map { ($0, score(subject, $0)) }.filter { $0.1.tier > .none }
            guard let best = scored.map({ $0.1.tier }).max() else { continue }
            let top = scored.filter { $0.1.tier == best }
            if top.count == 1, let one = top.first {
                suggestions.append(BLESuggestion(peripheralID: subject.id, deviceID: one.0.id,
                                                 tier: best, caption: one.1.caption))
            } else {
                let ids = top.map { $0.0.id }.sorted { $0.uuidString < $1.uuidString }
                ties.append(BLETie(peripheralID: subject.id, deviceIDs: ids, tier: best))
            }
        }
        return BLEMatchTable(suggestions: suggestions, ties: ties)
    }

    /// True when both are present and the first meaningful word of each, lowercased, is equal.
    public static func vendorsAgree(_ company: String?, _ manufacturer: String?) -> Bool {
        guard let c = firstMeaningfulWord(company), let m = firstMeaningfulWord(manufacturer) else { return false }
        return c == m
    }

    /// Place names and company-form words many vendors share, so they never decide agreement on their own.
    static let fillerWords: Set<String> = ["shenzhen", "beijing", "shanghai", "hangzhou", "guangdong", "dongguan", "the",
                                           "inc", "ltd", "co", "corp", "corporation", "limited", "llc", "gmbh"]

    /// The first word that is not filler; the first raw word when every word is filler.
    private static func firstMeaningfulWord(_ s: String?) -> String? {
        guard let s else { return nil }
        let words = s.lowercased().split(whereSeparator: { !$0.isLetter && !$0.isNumber }).map(String.init)
        return words.first { !fillerWords.contains($0) } ?? words.first
    }

    /// Lowercased, `.local` and a trailing " (N)" removed, non-alphanumerics dropped.
    public static func normalizedName(_ s: String) -> String {
        var t = s.lowercased()
        if t.hasSuffix(".local") { t.removeLast(6) }
        if let r = t.range(of: #"\s*\(\d+\)\s*$"#, options: .regularExpression) { t.removeSubrange(r) }
        return String(t.filter { $0.isLetter || $0.isNumber })
    }

    public static func namesSimilar(_ a: String, _ b: String) -> Bool {
        let x = normalizedName(a), y = normalizedName(b)
        if x.isEmpty || y.isEmpty { return false }
        if x == y { return true }
        let (short, long) = x.count <= y.count ? (x, y) : (y, x)
        return short.count >= 4 && long.contains(short)
    }
}
