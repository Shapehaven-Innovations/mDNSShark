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
}

/// Turns one advertisement into decoded frames and an inferred kind. Pure apart from the bundled tables.
public struct BLEAdvertisementParser: Sendable {
    private let companies: BLECompanyTable
    private let services: BLEServiceNameTable

    public init(companies: BLECompanyTable = .bundled, services: BLEServiceNameTable = .bundled) {
        self.companies = companies
        self.services = services
    }

    public func parse(_ fields: BLEAdvertisementFields) -> BLEParsedAdvertisement {
        let uuids = Array(Set(fields.serviceUUIDs.map(BLEServiceNameTable.shortForm))).sorted()
        var names: [String: String] = [:]
        for uuid in uuids { if let n = services.name(forUUID: uuid) { names[uuid] = n } }

        var data: [String: Data] = [:]
        for (key, value) in fields.serviceData { data[BLEServiceNameTable.shortForm(key)] = value }
        let matter = data[MatterBLEAdvertisement.serviceUUID].flatMap { MatterBLEAdvertisement.parse(serviceData: $0) }
        let eddystone = data[EddystoneFrame.serviceUUID].flatMap { EddystoneFrame.parse(serviceData: $0) }
        let fastPair = data[FastPairAdvertisement.serviceUUID].flatMap { FastPairAdvertisement.parse(serviceData: $0) }

        var continuity: [AppleContinuityMessage] = []
        var swiftPair: SwiftPairAdvertisement?
        let companyID = fields.companyID
        if let payload = fields.manufacturerPayload {
            if companyID == AppleContinuity.companyID { continuity = AppleContinuity.messages(in: payload) }
            else if companyID == SwiftPairAdvertisement.companyID { swiftPair = SwiftPairAdvertisement.parse(manufacturerPayload: payload) }
        }
        let homeKit = continuity.first { $0.type == .homeKit }.flatMap { HomeKitBLEAdvertisement.parse(continuityPayload: $0.payload) }
        let hint = continuity.first { $0.type == .proximityPairing }.flatMap { AppleContinuity.proximityPairingModelHint($0.payload) }

        let (kind, reason) = Self.classify(serviceUUIDs: uuids, matter: matter, eddystone: eddystone, fastPair: fastPair,
                                           swiftPair: swiftPair, continuity: continuity, homeKit: homeKit)
        return BLEParsedAdvertisement(
            displayName: BLEDisplayName.sanitized(fields.localName) ?? swiftPair?.displayName ?? BLEDisplayName.sanitized(fields.cachedName),
            companyID: companyID, companyName: companyID.flatMap { companies.name(for: $0) },
            serviceUUIDs: uuids, serviceNames: names, matter: matter, eddystone: eddystone, fastPair: fastPair,
            swiftPair: swiftPair, continuity: continuity, continuityModelHint: hint, homeKit: homeKit,
            kind: kind, kindReason: reason)
    }

    /// First hit wins; `.unknown` carries no reason.
    public static func classify(serviceUUIDs: [String], matter: MatterBLEAdvertisement?, eddystone: EddystoneFrame?, fastPair: FastPairAdvertisement?, swiftPair: SwiftPairAdvertisement?, continuity: [AppleContinuityMessage], homeKit: HomeKitBLEAdvertisement?) -> (kind: BLEKind, reason: String?) {
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
        if types.contains(.airPlayTarget) { return (.tv, "Sends an Apple AirPlay target message") }
        if types.contains(.findMy) { return (.tracker, "Sends an Apple Find My message") }
        if let t = [AppleContinuityType.handoff, .nearbyInfo, .nearbyAction, .airDrop, .airPlaySource, .tetheringSource].first(where: types.contains) {
            return (.phone, "Sends an Apple \(t.label) message")
        }
        if types.contains(.iBeacon) { return (.beacon, "Sends an iBeacon frame") }
        if eddystone != nil { return (.beacon, "Sends an Eddystone frame") }
        if let fastPair, fastPair.modelID != nil { return (.earbuds, "Advertises a Google Fast Pair model") }
        if swiftPair != nil { return (.inputDevice, "Sends a Microsoft Swift Pair beacon") }
        let uuids = Set(serviceUUIDs.map(BLEServiceNameTable.shortForm))
        if uuids.contains("1812") { return (.inputDevice, "Advertises the Human Interface Device service") }
        if uuids.contains("180D") { return (.health, "Advertises the Heart Rate service") }
        if uuids.contains("1809") { return (.health, "Advertises the Health Thermometer service") }
        if uuids.contains("1810") { return (.health, "Advertises the Blood Pressure service") }
        if uuids.contains("181D") { return (.health, "Advertises the Weight Scale service") }
        if uuids.contains("FEED") || uuids.contains("FEEC") { return (.tracker, "Advertises the Tile tracker service") }
        return (.unknown, nil)
    }
}
