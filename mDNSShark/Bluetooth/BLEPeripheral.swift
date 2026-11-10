import Foundation
import DeviceFingerprint

extension BLEKind {
    /// The LAN device chip this kind shares an icon and label with, or nil when it has none.
    var deviceType: DeviceType? {
        switch self {
        case .smartHome: return .smartHome
        case .audio, .earbuds: return .audio
        case .computer: return .computer
        case .tv: return .tv
        case .camera: return .camera
        case .printer: return .printer
        default: return nil
        }
    }
}

/// A stable-enough identity for one advertiser, used to join sightings under rotating identifiers.
struct BLEFingerprint: Hashable {
    enum Key: Hashable {
        case matter(vendorID: UInt16, productID: UInt16, discriminator: UInt16)
        case fastPair(UInt32)
        case name(String, companyID: UInt16?)
    }

    let key: Key

    /// Matter IDs with the discriminator first, then a Fast Pair model, then the sanitized name; nil when none exists.
    init?(parsed: BLEParsedAdvertisement) {
        if let m = parsed.matter {
            key = .matter(vendorID: m.vendorID, productID: m.productID, discriminator: m.discriminator)
        } else if let model = parsed.fastPair?.modelID {
            key = .fastPair(model)
        } else if let name = parsed.displayName {
            key = .name(name, companyID: parsed.companyID)
        } else {
            return nil
        }
    }
}

enum BLEDistance: String {
    case near, mid, far

    var label: String {
        switch self {
        case .near: return "Near"
        case .mid: return "Mid"
        case .far: return "Far"
        }
    }

    static func from(rssi: Int) -> BLEDistance {
        if rssi >= -60 { return .near }
        if rssi >= -80 { return .mid }
        return .far
    }
}

enum BLELifecycle: Equatable {
    case live, dim, expired

    static let dimAfter: TimeInterval = 60
    /// Unsaved rows are pruned at this age; saved rows are never pruned and show as their saved entry instead.
    static let dropAfter: TimeInterval = 120

    /// `markedStale` (a new scan started) forces at least `.dim`.
    static func of(lastSeen: Date, now: Date, markedStale: Bool) -> BLELifecycle {
        let age = now.timeIntervalSince(lastSeen)
        if age >= dropAfter { return .expired }
        if age >= dimAfter || markedStale { return .dim }
        return .live
    }
}

struct RSSIRingBuffer: Equatable {
    static let capacity = 32
    private(set) var samples: [Int]

    init() { samples = [] }

    mutating func append(_ value: Int) {
        samples.append(value)
        if samples.count > Self.capacity { samples.removeFirst(samples.count - Self.capacity) }
    }
}

struct BLESighting: Equatable {
    var identifier: UUID
    var fields: BLEAdvertisementFields
    var rssi: Int
    var at: Date
}

/// What a user-initiated GATT read returned. Every field is optional.
struct BLEDeviceInfo: Equatable, Codable {
    var manufacturer: String?
    var model: String?
    var firmware: String?
    var batteryPercent: Int?

    var isEmpty: Bool { manufacturer == nil && model == nil && firmware == nil && batteryPercent == nil }
}

enum BLEReadError: Error, Equatable {
    case notFound, connectFailed, timedOut, noServices, poweredOff, busy, notOffered
}

enum BLEReadState: Equatable {
    case idle, reading, done, failed(BLEReadError)
}

/// When one CoreBluetooth identifier joined a row and when it was last heard.
struct IdentifierTrace: Equatable {
    var joinedAt: Date
    var lastSeen: Date
    var lastRSSI: Int
}

struct BLEPeripheral: Identifiable, Equatable {
    /// Session-local row id; CoreBluetooth identifiers live in `identifierTraces`.
    let id: UUID
    var identifierTraces: [UUID: IdentifierTrace]
    var parsed: BLEParsedAdvertisement
    var fields: BLEAdvertisementFields
    var rssi: Int
    var rssiHistory: RSSIRingBuffer
    var firstSeen: Date
    /// Wall-clock time of the latest sighting.
    var lastSeen: Date
    /// The time aging counts from; it moves forward over app-inactive time, `lastSeen` never does.
    var agingAnchor: Date
    var markedStale: Bool
    var savedID: UUID?
    var deviceInfo: BLEDeviceInfo?
    var readState: BLEReadState
    /// The identifier that joined most recently, kept because two joins can share one timestamp.
    var lastJoined: UUID? = nil

    var identifiers: Set<UUID> { Set(identifierTraces.keys) }
    /// The identifier that joined last, the one a rotation would have moved to.
    var newestIdentifier: UUID? {
        if let lastJoined, identifierTraces[lastJoined] != nil { return lastJoined }
        return identifierTraces.max { a, b in
            a.value.joinedAt != b.value.joinedAt ? a.value.joinedAt < b.value.joinedAt : a.key.uuidString < b.key.uuidString
        }?.key
    }

    var displayName: String {
        if let name = parsed.displayName { return name }
        return BLEDisplayName.fallbackTitle(company: parsed.companyName, typeLabel: typeLabel, isTyped: parsed.kind != .unknown)
    }
    var fingerprint: BLEFingerprint? { BLEFingerprint(parsed: parsed) }
    var distance: BLEDistance { BLEDistance.from(rssi: rssi) }
    var icon: String { parsed.kind.deviceType?.symbol ?? parsed.kind.symbol }
    var typeLabel: String { parsed.kind.deviceType?.label ?? parsed.kind.label }

    func lifecycle(now: Date) -> BLELifecycle {
        BLELifecycle.of(lastSeen: agingAnchor, now: now, markedStale: markedStale)
    }
}

extension BLEPeripheral {
    /// Builds a row whose identifiers all joined at `firstSeen` and were last heard at `lastSeen`.
    init(id: UUID, identifiers: Set<UUID>, parsed: BLEParsedAdvertisement, fields: BLEAdvertisementFields, rssi: Int,
         rssiHistory: RSSIRingBuffer, firstSeen: Date, lastSeen: Date, markedStale: Bool, savedID: UUID?,
         deviceInfo: BLEDeviceInfo?, readState: BLEReadState) {
        let trace = IdentifierTrace(joinedAt: firstSeen, lastSeen: lastSeen, lastRSSI: rssi)
        self.init(id: id, identifierTraces: Dictionary(uniqueKeysWithValues: identifiers.map { ($0, trace) }),
                  parsed: parsed, fields: fields, rssi: rssi, rssiHistory: rssiHistory, firstSeen: firstSeen,
                  lastSeen: lastSeen, agingAnchor: lastSeen, markedStale: markedStale, savedID: savedID,
                  deviceInfo: deviceInfo, readState: readState)
    }
}
