import Foundation

public struct BLEParsedAdvertisement: Equatable, Sendable {
    public var displayName: String?
    public var companyID: UInt16?
    public var companyName: String?
    public var serviceUUIDs: [String]
    public var serviceNames: [String: String]
    public var matter: MatterBLEAdvertisement?
    public var eddystone: EddystoneFrame?
    public var fastPair: FastPairAdvertisement?
    public var swiftPair: SwiftPairAdvertisement?
    public var continuity: [AppleContinuityMessage]
    public var continuityModelHint: String?
    public var homeKit: HomeKitBLEAdvertisement?
    public var kind: BLEKind
    public var kindReason: String?
    public var cdp: CDPBeacon? = nil
    public var hint: BLEFrameHint? = nil
}

/// Turns one advertisement into decoded frames and an inferred kind. Pure apart from the bundled tables.
public struct BLEAdvertisementParser: Sendable {
    private let companies: BLECompanyTable
    private let services: BLEServiceNameTable
    private let members: BLEServiceNameTable

    public init(companies: BLECompanyTable = .bundled, services: BLEServiceNameTable = .bundled, members: BLEServiceNameTable = .bundledMembers) {
        self.members = members
        self.companies = companies
        self.services = services
    }

    public func parse(_ fields: BLEAdvertisementFields) -> BLEParsedAdvertisement {
        let uuids = Array(Set(fields.serviceUUIDs.map(BLEServiceNameTable.shortForm))).sorted()
        var names: [String: String] = [:]
        for uuid in uuids { if let n = services.name(forUUID: uuid) ?? members.name(forUUID: uuid) { names[uuid] = n } }

        var data: [String: Data] = [:]
        for (key, value) in fields.serviceData { data[BLEServiceNameTable.shortForm(key)] = value }
        let matter = data[MatterBLEAdvertisement.serviceUUID].flatMap { MatterBLEAdvertisement.parse(serviceData: $0) }
        let eddystone = data[EddystoneFrame.serviceUUID].flatMap { EddystoneFrame.parse(serviceData: $0) }
        let fastPair = data[FastPairAdvertisement.serviceUUID].flatMap { FastPairAdvertisement.parse(serviceData: $0) }

        var continuity: [AppleContinuityMessage] = []
        var swiftPair: SwiftPairAdvertisement?
        var cdp: CDPBeacon?
        let companyID = fields.companyID
        if let payload = fields.manufacturerPayload {
            if companyID == AppleContinuity.companyID { continuity = AppleContinuity.messages(in: payload) }
            else if companyID == SwiftPairAdvertisement.companyID { swiftPair = SwiftPairAdvertisement.parse(manufacturerPayload: payload)
                cdp = CDPBeacon.parse(manufacturerPayload: payload)
            }
        }
        let homeKit = continuity.first { $0.type == .homeKit }.flatMap { HomeKitBLEAdvertisement.parse(continuityPayload: $0.payload) }
        let hint = continuity.first { $0.type == .proximityPairing }.flatMap { AppleContinuity.proximityPairingModelHint($0.payload) }

        // Service data keys count as advertised services for classification; the shown list stays literal.
        let frameHint = BLEFrameHint.hint(keys: Set(uuids + data.keys), serviceData: data, solicited: Set(fields.solicitedServiceUUIDs.map(BLEServiceNameTable.shortForm)),
                                       companyID: companyID, manufacturerPayload: Array(fields.manufacturerPayload ?? Data()),
                                       memberOwner: { self.members.name(forUUID: $0) })
        var (kind, reason) = Self.classify(serviceUUIDs: uuids + data.keys.sorted(), matter: matter, eddystone: eddystone,
                                           continuity: continuity, homeKit: homeKit)
        if kind == .findMy, let status = continuity.first(where: { $0.type == .findMy })?.payload.first {
            // Status bits 4 and 5 give the device class (AirGuard). Inferred from open source, not Apple documentation.
            let classes = ["an Apple device", "an AirTag", "a third party accessory", "AirPods"]
            reason = "Sends an Apple Find My message; its status byte suggests \(classes[Int((status >> 4) & 0x03)]) (inferred)"
        }
        if kind == .unknown, let frameHint { (kind, reason) = (frameHint.kind, frameHint.reason) }
        return BLEParsedAdvertisement(
            displayName: BLEDisplayName.sanitized(fields.localName) ?? swiftPair?.displayName ?? BLEDisplayName.sanitized(fields.cachedName),
            companyID: companyID, companyName: companyID.flatMap { companies.name(for: $0) },
            serviceUUIDs: uuids, serviceNames: names, matter: matter, eddystone: eddystone, fastPair: fastPair,
            swiftPair: swiftPair, continuity: continuity, continuityModelHint: hint, homeKit: homeKit,
            kind: kind, kindReason: reason, cdp: cdp, hint: frameHint)
    }

    /// First hit wins; `.unknown` carries no reason. Only evidence that names one product category sets a kind.
    public static func classify(serviceUUIDs: [String], matter: MatterBLEAdvertisement?, eddystone: EddystoneFrame?, continuity: [AppleContinuityMessage], homeKit: HomeKitBLEAdvertisement?) -> (kind: BLEKind, reason: String?) {
        if matter != nil { return (.smartHome, "Advertises a Matter commissioning service") }
        if let homeKit {
            switch homeKit.categoryKind {
            case .camera: return (.camera, "Advertises a HomeKit camera category")
            case .audio: return (.audio, "Advertises a HomeKit audio category")
            case .tv: return (.tv, "Advertises a HomeKit television category")
            default: return (.smartHome, "Advertises a HomeKit accessory")
            }
        }
        let types = Set(continuity.compactMap(\.type))
        if types.contains(.proximityPairing) { return (.earbuds, "Sends Apple Proximity Pairing data") }
        if types.contains(.magicSwitch) { return (.wearable, "Sends Apple Magic Switch data") }
        if types.contains(.findMy) { return (.findMy, "Sends an Apple Find My message") }
        if types.contains(.iBeacon) { return (.beacon, "Sends an iBeacon frame") }
        switch eddystone {
        case .findHub?: return (.tracker, "Sends a Google Find Hub frame")
        case .uid?, .url?, .tlm?, .eid?: return (.beacon, "Sends an Eddystone frame")
        case .unknown?, nil: break
        }
        let uuids = Set(serviceUUIDs.map(BLEServiceNameTable.shortForm))
        if uuids.contains("1812") { return (.inputDevice, "Advertises the Human Interface Device service") }
        if uuids.contains("180D") { return (.health, "Advertises the Heart Rate service") }
        if uuids.contains("1809") { return (.health, "Advertises the Health Thermometer service") }
        if uuids.contains("1810") { return (.health, "Advertises the Blood Pressure service") }
        if uuids.contains("181D") { return (.health, "Advertises the Weight Scale service") }
        // Further SIG-assigned services, each named by the Bluetooth SIG for one product category.
        let healthServices = ["1808": "Glucose", "181F": "Continuous Glucose Monitoring", "1822": "Pulse Oximeter",
                              "183A": "Insulin Delivery", "181B": "Body Composition", "1854": "Hearing Access"]
        if let id = healthServices.keys.sorted().first(where: uuids.contains) { return (.health, "Advertises the \(healthServices[id]!) service") }
        if uuids.contains("184E") { return (.audio, "Advertises the Audio Stream Control service") }
        if uuids.contains("1850") { return (.audio, "Advertises the Published Audio Capabilities service") }
        if uuids.contains("FEED") || uuids.contains("FEEC") { return (.tracker, "Advertises the Tile tracker service") }
        return (.unknown, nil)
    }
}
