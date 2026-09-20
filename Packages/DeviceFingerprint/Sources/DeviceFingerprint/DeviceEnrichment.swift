/// Where a piece of enrichment data came from — used only to order precedence
/// when two sources disagree. Never shown to the user directly.
public enum EnrichmentSource: Int, Comparable {
    case ubiquitiDiscovery   // ground truth: the device told us
    case ouiLookup           // mDNS-TXT MAC resolved through the OUI table
    case ssdpDescription     // UPnP device-description XML
    case portBanner          // TCP banner-grab guess
    case ttlGuess            // weakest: IP TTL heuristic

    public static func < (lhs: EnrichmentSource, rhs: EnrichmentSource) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

/// One probe's partial result for a single device.
public struct DeviceEnrichment {
    public let mac: String?
    public let manufacturer: String?
    public let inferredOS: String?
    public let openPorts: [Int]
    public let source: EnrichmentSource

    public init(mac: String?, manufacturer: String?, inferredOS: String?, openPorts: [Int], source: EnrichmentSource) {
        self.mac = mac; self.manufacturer = manufacturer; self.inferredOS = inferredOS
        self.openPorts = openPorts; self.source = source
    }
}

/// The subset of `DiscoveredDevice`'s fields this merge operates on — kept
/// as a plain struct here so the package has no dependency on the app
/// target's `DiscoveredDevice` type.
public struct EnrichedFields {
    public var mac: String?
    public var manufacturer: String?
    public var inferredOS: String?
    public var openPorts: [Int]

    public init(mac: String?, manufacturer: String?, inferredOS: String?, openPorts: [Int]) {
        self.mac = mac; self.manufacturer = manufacturer; self.inferredOS = inferredOS
        self.openPorts = openPorts
    }
}

/// Folds a batch of probe results into the fields already known for a
/// device. Ubiquiti discovery replies are ground truth and win outright for
/// mac/manufacturer/inferredOS; otherwise the lowest-`rawValue` (strongest)
/// source with a non-nil answer wins per field, independently. `openPorts`
/// is always a union, never overwritten.
public func merge(existing: EnrichedFields, incoming: [DeviceEnrichment]) -> EnrichedFields {
    var result = existing

    if let ubnt = incoming.first(where: { $0.source == .ubiquitiDiscovery }) {
        result.mac = ubnt.mac ?? result.mac
        result.manufacturer = ubnt.manufacturer ?? result.manufacturer
        result.inferredOS = ubnt.inferredOS ?? result.inferredOS
    }

    let byStrength = incoming.sorted { $0.source < $1.source }
    if result.mac == nil { result.mac = byStrength.first(where: { $0.mac != nil })?.mac }
    if result.manufacturer == nil { result.manufacturer = byStrength.first(where: { $0.manufacturer != nil })?.manufacturer }
    if result.inferredOS == nil { result.inferredOS = byStrength.first(where: { $0.inferredOS != nil })?.inferredOS }

    var ports = Set(result.openPorts)
    for e in incoming { ports.formUnion(e.openPorts) }
    result.openPorts = Array(ports).sorted()

    return result
}
