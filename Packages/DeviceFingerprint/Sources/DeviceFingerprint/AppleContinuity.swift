import Foundation

public enum AppleContinuityType: UInt8, CaseIterable, Sendable {
    case iBeacon = 0x02, airDrop = 0x05, homeKit = 0x06, proximityPairing = 0x07, heySiri = 0x08
    case airPlayTarget = 0x09, airPlaySource = 0x0A, magicSwitch = 0x0B, handoff = 0x0C
    case tetheringTarget = 0x0D, tetheringSource = 0x0E, nearbyAction = 0x0F, nearbyInfo = 0x10, findMy = 0x12

    public var label: String {
        switch self {
        case .iBeacon: return "iBeacon"
        case .airDrop: return "AirDrop"
        case .homeKit: return "HomeKit"
        case .proximityPairing: return "Proximity Pairing"
        case .heySiri: return "Hey Siri"
        case .airPlayTarget: return "AirPlay target"
        case .airPlaySource: return "AirPlay source"
        case .magicSwitch: return "Magic Switch"
        case .handoff: return "Handoff"
        case .tetheringTarget: return "Tethering target"
        case .tetheringSource: return "Tethering source"
        case .nearbyAction: return "Nearby Action"
        case .nearbyInfo: return "Nearby Info"
        case .findMy: return "Find My"
        }
    }
}

public struct AppleContinuityMessage: Equatable, Sendable {
    public var rawType: UInt8
    public var type: AppleContinuityType?
    public var payload: Data

    public init(rawType: UInt8, type: AppleContinuityType?, payload: Data) {
        self.rawType = rawType
        self.type = type
        self.payload = payload
    }
}

public enum AppleContinuity {
    public static let companyID: UInt16 = 0x004C

    /// Walks type, length, payload records; a truncated record ends the walk.
    public static func messages(in manufacturerPayload: Data) -> [AppleContinuityMessage] {
        let b = Array(manufacturerPayload)
        var result: [AppleContinuityMessage] = []
        var i = 0
        while i + 2 <= b.count {
            let type = b[i]
            let length = Int(b[i + 1])
            guard i + 2 + length <= b.count else { break }
            result.append(AppleContinuityMessage(rawType: type, type: AppleContinuityType(rawValue: type), payload: Data(b[(i + 2)..<(i + 2 + length)])))
            i += 2 + length
        }
        return result
    }

    /// Model hints from public observation of Proximity Pairing codes; each value is a model hint, checked on device in the Task 15 checklist.
    public static let proximityPairingModels: [UInt16: String] = [
        0x0220: "AirPods", 0x0F20: "AirPods (2nd generation)", 0x1320: "AirPods (3rd generation)",
        0x0E20: "AirPods Pro", 0x1420: "AirPods Pro (2nd generation)", 0x0A20: "AirPods Max",
        0x0520: "BeatsX", 0x0620: "Beats Solo3", 0x0920: "Beats Studio3", 0x0B20: "Powerbeats Pro", 0x1020: "Beats Flex",
    ]

    /// The model code is the big endian UInt16 at payload bytes 1 and 2.
    public static func proximityPairingModelHint(_ payload: Data) -> String? {
        let b = Array(payload)
        guard b.count >= 3 else { return nil }
        let code = UInt16(b[1]) << 8 | UInt16(b[2])
        return BLEServiceNameTable.bundledAppleProximity.name(forUUID: String(format: "%04X", code)) ?? proximityPairingModels[code]
    }
}
