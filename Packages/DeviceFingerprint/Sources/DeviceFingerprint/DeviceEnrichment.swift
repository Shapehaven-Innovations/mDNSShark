/// Where a piece of enrichment data came from — used only to order precedence
/// when two sources disagree. Never shown to the user directly.
public enum EnrichmentSource: Int, Comparable {
    case ubiquitiDiscovery   // ground truth: the device told us
    case asusDiscovery       // ground truth: the device told us (ASUS infosvr)
    case jnapHnapDiscovery   // ground truth: the device told us (Linksys JNAP / HNAP)
    case googleWifiDiscovery // ground truth: the device told us (Google Wifi /api/v1/status)
    case ouiLookup           // mDNS-TXT MAC resolved through the OUI table
    case ssdpDescription     // UPnP device-description XML
    case portBanner          // TCP banner-grab guess
    case ttlGuess            // weakest: IP TTL heuristic

    public static func < (lhs: EnrichmentSource, rhs: EnrichmentSource) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    /// True for sources where the device directly told us about itself via
    /// its own vendor discovery protocol (as opposed to an OUI table
    /// lookup, a UPnP description fetch, a banner-grab guess, or a TTL
    /// heuristic). `merge()` lets any ground-truth source unconditionally
    /// win mac/manufacturer/inferredOS over whatever `existing` already
    /// holds, picking the strongest ground-truth source when more than one
    /// answered. Add new vendor-discovery sources here instead of
    /// hardcoding another `$0.source == .someCase` check in `merge()`.
    public var isGroundTruth: Bool {
        switch self {
        case .ubiquitiDiscovery, .asusDiscovery, .jnapHnapDiscovery, .googleWifiDiscovery: return true
        case .ouiLookup, .ssdpDescription, .portBanner, .ttlGuess: return false
        }
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
/// device. Ground-truth discovery replies (see `EnrichmentSource.isGroundTruth`
/// — currently Ubiquiti, ASUS, Linksys JNAP/HNAP, and Google Wifi) win outright for mac/manufacturer/inferredOS,
/// using the strongest ground-truth source when more than one answered;
/// otherwise the lowest-`rawValue` (strongest) source with a non-nil answer
/// wins per field, independently. `openPorts` is always a union, never
/// overwritten.
public func merge(existing: EnrichedFields, incoming: [DeviceEnrichment]) -> EnrichedFields {
    var result = existing

    if let groundTruth = incoming.filter({ $0.source.isGroundTruth }).min(by: { $0.source < $1.source }) {
        result.mac = groundTruth.mac ?? result.mac
        result.manufacturer = groundTruth.manufacturer ?? result.manufacturer
        result.inferredOS = groundTruth.inferredOS ?? result.inferredOS
    }

    let byStrength = incoming.sorted { $0.source < $1.source }
    if result.mac == nil { result.mac = byStrength.first(where: { $0.mac != nil })?.mac }
    if result.manufacturer == nil { result.manufacturer = byStrength.first(where: { $0.manufacturer != nil })?.manufacturer }
    if result.inferredOS == nil { result.inferredOS = byStrength.first(where: { $0.inferredOS != nil })?.inferredOS }

    // Deliberately NOT applying `inferredOSFamily`'s manufacturer-based
    // fallback here. `merge()` is called incrementally — each call's
    // `existing` is a PREVIOUS call's output — and this function's own
    // precedence rule only lets a field be filled once per non-ground-truth
    // source (`result.inferredOS == nil` above). Writing a generic guess
    // into `result.inferredOS` the first time a manufacturer becomes known
    // would permanently block a later, genuinely more specific
    // non-ground-truth answer (e.g. a real "luci"/OpenWrt banner hit
    // arriving in a slower probe batch after a faster SSDP fetch already
    // resolved just the manufacturer) from ever landing, since the field
    // would no longer look empty. Callers apply `inferredOSFamily` as a
    // display-time fallback instead — see `DiscoveredDevice.displayInferredOS`
    // — computed fresh every time, so it can never block a real update.

    var ports = Set(result.openPorts)
    for e in incoming { ports.formUnion(e.openPorts) }
    result.openPorts = Array(ports).sorted()

    return result
}
