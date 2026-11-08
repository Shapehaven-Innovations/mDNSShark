import Foundation
import DeviceFingerprint

/// A Bluetooth device the user chose to remember. These are the only fields ever written to disk.
struct BLESavedDevice: Codable, Identifiable, Equatable {
    var id: UUID
    var name: String?
    var companyID: UInt16?
    var companyName: String?
    var serviceUUIDs: [String]
    var matterVendorID: UInt16?
    var matterProductID: UInt16?
    /// Optional so files written before it existed still decode.
    var matterDiscriminator: UInt16?
    var fastPairModelID: UInt32?
    var kind: BLEKind
    var notes: String
    var addedAt: Date
    var lastSeenAt: Date

    init(peripheral: BLEPeripheral, now: Date) {
        let parsed = peripheral.parsed
        id = UUID()
        name = parsed.displayName
        companyID = parsed.companyID
        companyName = parsed.companyName
        serviceUUIDs = parsed.serviceUUIDs
        matterVendorID = parsed.matter?.vendorID
        matterProductID = parsed.matter?.productID
        matterDiscriminator = parsed.matter?.discriminator
        fastPairModelID = parsed.fastPair?.modelID
        kind = parsed.kind
        notes = ""
        addedAt = now
        lastSeenAt = now
    }

    /// Same priority as `BLEFingerprint(parsed:)`: Matter IDs and discriminator, then Fast Pair model, then name.
    var fingerprint: BLEFingerprint? {
        if let v = matterVendorID, let p = matterProductID, let d = matterDiscriminator {
            return BLEFingerprint(key: .matter(vendorID: v, productID: p, discriminator: d))
        }
        if let model = fastPairModelID { return BLEFingerprint(key: .fastPair(model)) }
        if let name { return BLEFingerprint(key: .name(name, companyID: companyID)) }
        return nil
    }

    var displayName: String {
        if let name { return name }
        return kind == .unknown ? BLEDisplayName.unnamed : "\(BLEDisplayName.unnamed) \(typeLabel)"
    }
    var icon: String { kind.deviceType?.symbol ?? kind.symbol }
    var typeLabel: String { kind.deviceType?.label ?? kind.label }
}

extension BLEFingerprint {
    init(key: Key) { self.key = key }
}

/// Saved Bluetooth devices in the app's own Application Support, never the App Group.
@MainActor
final class BLEDeviceStore {
    private let fileURL: URL
    private(set) var devices: [BLESavedDevice] = []
    /// The file as read, when some entries could not be decoded; copied aside before the first write drops them.
    private var partialOriginal: Data?

    init(fileURL: URL) { self.fileURL = fileURL }

    static func appSupport() -> BLEDeviceStore {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return BLEDeviceStore(fileURL: base.appendingPathComponent("Bluetooth/saved-devices.json"))
    }

    /// A missing file leaves the list empty; an unreadable one is moved aside first, so no later write destroys it.
    func load() {
        partialOriginal = nil
        guard let data = try? Data(contentsOf: fileURL) else {
            devices = []
            return
        }
        guard let lenient = try? Self.decodeLenient(data) else {
            if let aside = corruptCopyURL() { try? FileManager.default.moveItem(at: fileURL, to: aside) }
            devices = []
            return
        }
        devices = lenient.devices
        if lenient.skipped > 0 { partialOriginal = data }
    }

    /// `saved-devices.corrupt-<ISO 8601 basic>.json` beside the file, with a counter if that name is taken.
    private func corruptCopyURL() -> URL? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withYear, .withMonth, .withDay, .withTime, .withTimeZone]
        let stem = "\(fileURL.deletingPathExtension().lastPathComponent).corrupt-\(formatter.string(from: Date()))"
        let dir = fileURL.deletingLastPathComponent()
        for n in 0..<100 {
            let candidate = dir.appendingPathComponent(n == 0 ? "\(stem).json" : "\(stem)-\(n).json")
            if !FileManager.default.fileExists(atPath: candidate.path) { return candidate }
        }
        return nil
    }

    func add(_ device: BLESavedDevice) throws {
        var next = devices
        next.removeAll { $0.id == device.id }
        next.append(device)
        try commit(next)
    }

    func update(_ device: BLESavedDevice) throws {
        guard let index = devices.firstIndex(where: { $0.id == device.id }) else { return }
        var next = devices
        next[index] = device
        try commit(next)
    }

    func remove(id: UUID) throws {
        guard devices.contains(where: { $0.id == id }) else { return }
        try commit(devices.filter { $0.id != id })
    }

    /// Folds `source` into `target`, keeping the target's id, then removes `source`.
    func merge(_ source: UUID, into target: UUID) throws {
        guard source != target,
              let s = devices.first(where: { $0.id == source }),
              var t = devices.first(where: { $0.id == target }) else { return }
        t.addedAt = min(t.addedAt, s.addedAt)
        t.lastSeenAt = max(t.lastSeenAt, s.lastSeenAt)
        t.serviceUUIDs = Array(Set(t.serviceUUIDs).union(s.serviceUUIDs)).sorted()
        t.name = t.name ?? s.name
        t.companyID = t.companyID ?? s.companyID
        t.companyName = t.companyName ?? s.companyName
        // Matter IDs travel as one set from one entry, so a vendor never pairs with another entry's product.
        if !(t.matterVendorID != nil && t.matterProductID != nil), s.matterVendorID != nil, s.matterProductID != nil {
            t.matterVendorID = s.matterVendorID
            t.matterProductID = s.matterProductID
            t.matterDiscriminator = s.matterDiscriminator
        }
        t.fastPairModelID = t.fastPairModelID ?? s.fastPairModelID
        if t.kind == .unknown { t.kind = s.kind }
        t.notes = [t.notes, s.notes].filter { !$0.isEmpty }.joined(separator: "\n")
        var next = devices.filter { $0.id != source }
        if let index = next.firstIndex(where: { $0.id == target }) { next[index] = t }
        try commit(next)
    }

    static func encode(_ devices: [BLESavedDevice]) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(devices)
    }

    static func decode(_ data: Data) throws -> [BLESavedDevice] {
        try decodeLenient(data).devices
    }

    /// One bad entry is skipped instead of failing the file; throws only when the file is not a JSON array.
    static func decodeLenient(_ data: Data) throws -> (devices: [BLESavedDevice], skipped: Int) {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let entries = try decoder.decode([Lenient].self, from: data)
        let devices = entries.compactMap(\.device)
        return (devices, entries.count - devices.count)
    }

    private struct Lenient: Decodable {
        let device: BLESavedDevice?
        init(from decoder: Decoder) throws { device = try? BLESavedDevice(from: decoder) }
    }

    /// Writes first, then publishes, so a failed save leaves the in-memory list unchanged.
    private func commit(_ next: [BLESavedDevice]) throws {
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let original = partialOriginal, let aside = corruptCopyURL() {
            try original.write(to: aside, options: .atomic)
            partialOriginal = nil
        }
        try Self.encode(next).write(to: fileURL, options: .atomic)
        devices = next
    }
}
