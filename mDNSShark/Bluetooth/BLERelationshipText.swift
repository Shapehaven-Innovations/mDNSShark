import Foundation
import DeviceFingerprint

/// The "Topology relationship" wording for both sides of a Bluetooth suggestion. Every line is an inference.
enum BLERelationshipText {
    struct Line: Equatable {
        var title: String
        var caption: String?
        var tier: BLEMatchTier?
        var peripheralID: UUID?
        var deviceID: UUID?
    }

    static let heading = "Topology relationship"
    static let noSuggestion = "No Bluetooth device suggested"
    static let notOnNetwork = "Not on network"
    static let savedBluetoothOnly = "Saved, Bluetooth only"
    static let savedNotSeen = "Saved, not seen now"

    static func badge(_ tier: BLEMatchTier) -> String {
        tier == .strong ? "Strong, inferred" : "Possible, inferred"
    }

    /// Nil when no Bluetooth scan ran this session, so the card is omitted.
    static func forLANDevice(deviceID: UUID, table: BLEMatchTable, peripheralName: (UUID) -> String,
                             deviceName: (UUID) -> String, scanRanThisSession: Bool) -> [Line]? {
        guard scanRanThisSession else { return nil }
        var lines: [Line] = table.suggestions(forDevice: deviceID).map { s in
            let name = peripheralName(s.peripheralID)
            let title = s.tier == .strong ? "Suggested device: \(name)" : "Possibly \(name)?"
            return Line(title: title, caption: s.caption, tier: s.tier, peripheralID: s.peripheralID, deviceID: deviceID)
        }
        for tie in table.ties(forDevice: deviceID) {
            let others = tie.deviceIDs.filter { $0 != deviceID }
            let caption = others.count == 1 ? "Also fits \(deviceName(others[0]))." : "Also fits \(others.count) other devices."
            lines.append(Line(title: "Could be \(peripheralName(tie.peripheralID))", caption: caption, tier: tie.tier,
                              peripheralID: tie.peripheralID, deviceID: deviceID))
        }
        return lines.isEmpty ? [Line(title: noSuggestion)] : lines
    }

    static func forPeripheral(peripheralID: UUID, table: BLEMatchTable, isSaved: Bool,
                              deviceName: (UUID) -> String, deviceIP: (UUID) -> String?) -> Line {
        if let s = table.suggestion(forPeripheral: peripheralID) {
            let name = deviceName(s.deviceID)
            let title = deviceIP(s.deviceID).map { "Possibly \(name) (\($0))?" } ?? "Possibly \(name)?"
            return Line(title: title, caption: s.caption, tier: s.tier, peripheralID: peripheralID, deviceID: s.deviceID)
        }
        if let tie = table.tie(forPeripheral: peripheralID), let first = tie.deviceIDs.first {
            let others = tie.deviceIDs.count - 1
            let tail = others == 1 ? "1 other device" : "\(others) other devices"
            return Line(title: "Could be \(deviceName(first)), also fits \(tail)", tier: tie.tier,
                        peripheralID: peripheralID, deviceID: first)
        }
        return Line(title: isSaved ? savedBluetoothOnly : notOnNetwork, peripheralID: peripheralID)
    }
}
