import Foundation

/// A label and category taken from an advertisement's service UUIDs, service data or manufacturer data
/// when nothing advertises a name. Rules come from published specs and open decoders; see `rules`.
public struct BLEFrameHint: Equatable, Sendable {
    public var label: String
    public var kind: BLEKind
    public var reason: String

    /// Service UUID or service data key (16-bit short form, upper case) to what advertises it.
    /// Owners come from the Bluetooth SIG member UUID list; the product meaning from each vendor's spec or decoder.
    static let services: [(key: String, label: String, kind: BLEKind)] = [
        ("FD5A", "Samsung SmartTag", .tracker), ("FD59", "Samsung SmartTag (not set up)", .tracker),
        ("FD69", "Samsung Galaxy device (offline finding)", .tracker),
        ("FEED", "Tile tracker", .tracker), ("FEEC", "Tile tracker", .tracker),
        ("FE33", "Chipolo tracker", .tracker), ("FA25", "Pebblebee tracker", .tracker),
        ("FCB2", "Location tracker", .tracker),
        ("FE95", "Xiaomi device", .smartHome), ("FD3D", "SwitchBot device", .smartHome),
        ("FCD2", "BTHome sensor", .smartHome), ("FE0F", "Philips Hue light", .smartHome),
        ("FE24", "August or Yale lock", .smartHome), ("FDCD", "Qingping sensor", .smartHome),
        ("FE07", "Sonos speaker", .audio), ("FEBE", "Bose audio device", .audio), ("FDD2", "Bose audio device", .audio),
        ("FEFF", "Jabra headset", .earbuds),
        ("1852", "Auracast broadcast", .audio), ("1856", "Auracast broadcast", .audio),
        ("184E", "LE Audio device", .audio), ("1853", "LE Audio device", .audio),
        ("1855", "LE Audio device", .audio), ("1858", "LE Audio gaming device", .audio),
        ("1854", "Hearing aid", .health), ("FDF0", "Hearing aid", .health),
        ("FE1F", "Garmin device", .wearable), ("FEE0", "Mi Band or Amazfit", .wearable), ("FEE1", "Mi Band or Amazfit", .wearable),
        ("FD6F", "Exposure notification beacon", .phone),
        ("180D", "Heart rate sensor", .health), ("1816", "Cycling sensor", .health), ("1818", "Bike power meter", .health),
        ("1814", "Running sensor", .health), ("1826", "Fitness machine", .health), ("1822", "Pulse oximeter", .health),
        ("1809", "Thermometer", .health), ("1810", "Blood pressure monitor", .health), ("181D", "Scale", .health),
        ("1808", "Glucose monitor", .health), ("181F", "Glucose monitor", .health),
        ("1812", "Keyboard, mouse or remote", .inputDevice),
    ]

    /// Samsung (company 0x0075) EasySetup popup prefixes for Galaxy Buds and Galaxy Watch.
    private static let samsungBudsPrefix: [UInt8] = [0x42, 0x09, 0x81, 0x02, 0x14, 0x15, 0x03, 0x21, 0x01, 0x09]
    private static let samsungWatchPrefix: [UInt8] = [0x01, 0x00, 0x02, 0x00, 0x01, 0x01, 0xFF, 0x00, 0x00, 0x43]

    /// Companies whose IDs sit on thousands of unrelated products (chip makers); never a device label.
    public static let chipVendorCompanyIDs: Set<UInt16> = [0x0059, 0x02E5, 0x0211, 0x05D6, 0x02B0, 0x0094, 0x000A, 0x001D, 0x000F]

    /// `keys` are the short-form UUIDs of advertised services plus service data keys.
    public static func hint(keys: Set<String>, serviceData: [String: Data] = [:], solicited: Set<String> = [], companyID: UInt16?,
                            manufacturerPayload: [UInt8], memberOwner: (String) -> String? = { _ in nil },
                            matchers: BLEMatcherTable = .bundled) -> BLEFrameHint? {
        if companyID == 0x0075 {
            if manufacturerPayload.starts(with: samsungBudsPrefix) {
                return BLEFrameHint(label: "Samsung Galaxy Buds", kind: .earbuds, reason: "Sends a Samsung Galaxy Buds pairing frame")
            }
            if manufacturerPayload.starts(with: samsungWatchPrefix) {
                return BLEFrameHint(label: "Samsung Galaxy Watch", kind: .wearable, reason: "Sends a Samsung Galaxy Watch pairing frame")
            }
        }
        // Xiaomi MiBeacon carries a product id in service data bytes 2 and 3 (little endian), readable even when the payload is encrypted.
        if let frame = serviceData["FE95"].map(Array.init), frame.count >= 4,
           let product = BLEServiceNameTable.bundledXiaomiProducts.name(forUUID: String(format: "%02X%02X", frame[3], frame[2])) {
            return BLEFrameHint(label: "Xiaomi \(product)", kind: .smartHome, reason: "Sends a Xiaomi MiBeacon frame for this product")
        }
        // Table order is priority: the specific product frames come before the generic SIG service categories.
        for rule in services where keys.contains(rule.key) {
            return BLEFrameHint(label: rule.label, kind: rule.kind, reason: "Advertises service \(rule.key)")
        }
        if let found = matchers.match(companyID: companyID, manufacturerPayload: manufacturerPayload, keys: keys, serviceDataKeys: Set(serviceData.keys)) {
            return BLEFrameHint(label: found.label, kind: found.kind, reason: "Matches a published \(found.label) advertisement pattern")
        }
        // A peripheral that asks the phone to host ANCS or AMS is an accessory for an iPhone, not an iPhone.
        if !solicited.isDisjoint(with: ancsAmsUUIDs) {
            return BLEFrameHint(label: "iPhone accessory", kind: .unknown, reason: "Asks an iPhone to host Apple notification or media services")
        }
        // Last resort: the company registered for a member service UUID, unless that owner says nothing about the product.
        for key in keys.sorted() where key.count == 4 {
            guard let owner = memberOwner(key), let short = BLEDisplayName.shortCompany(owner), !isChipVendorName(owner) else { continue }
            return BLEFrameHint(label: "\(short) device", kind: .unknown, reason: "Advertises a service registered to \(short)")
        }
        return nil
    }

    private static let ancsAmsUUIDs: Set<String> = ["7905F431-B5CE-4E99-A40F-4B1E122D00D0", "89D3502B-0F36-433A-8EF4-C502AD55F8DC"]

    private static func isChipVendorName(_ name: String) -> Bool {
        let lower = name.lowercased()
        return ["nordic", "espressif", "telink", "qualcomm", "broadcom", "airoha", "bestechnic", "jieli", "silicon lab", "texas instruments", "dialog"]
            .contains { lower.contains($0) }
    }
}
