import Foundation

/// Turns the in-memory advertisement log into JSON or CSV for a user-started share.
enum BLEAdvertisementLogExport {
    static let label = "Advertisement log, not a link-layer capture"
    static let csvHeader = "time,peripheral,name,company_id,company,service_uuids,rssi_dbm,tx_power,connectable,manufacturer_data_hex,service_data_hex"

    private struct Document: Encodable {
        let label: String
        let records: [BLEAdvertisementRecord]
    }

    static func json(_ records: [BLEAdvertisementRecord]) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        let iso = isoFormatter()
        encoder.dateEncodingStrategy = .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(iso.string(from: date))
        }
        return try encoder.encode(Document(label: label, records: records))
    }

    static func csv(_ records: [BLEAdvertisementRecord]) -> String {
        let iso = isoFormatter()
        var out = csvHeader + "\r\n"
        for r in records {
            let serviceData = r.serviceDataHex.keys.sorted().map { "\($0)=\(r.serviceDataHex[$0] ?? "")" }.joined(separator: ";")
            // Numbers go out unescaped so a negative RSSI is not mistaken for a formula and prefixed.
            let fields: [String] = [
                iso.string(from: r.at),
                r.peripheralID.uuidString,
                csvField(r.name ?? ""),
                r.companyID.map { String(format: "0x%04X", $0) } ?? "",
                csvField(r.companyName ?? ""),
                csvField(r.serviceUUIDs.joined(separator: ";")),
                String(r.rssi),
                r.txPower.map(String.init) ?? "",
                r.isConnectable.map { $0 ? "true" : "false" } ?? "",
                csvField(r.manufacturerDataHex ?? ""),
                csvField(serviceData),
            ]
            out += fields.joined(separator: ",") + "\r\n"
        }
        return out
    }

    /// Quotes a text field when it holds a delimiter and defuses spreadsheet formulas with a leading single quote.
    static func csvField(_ value: String) -> String {
        var text = value
        if let first = text.unicodeScalars.first, "=+-@\t\r".unicodeScalars.contains(first) {
            text = "'" + text
        }
        if text.contains(where: { $0 == "," || $0 == "\"" || $0 == "\r" || $0 == "\n" || $0 == "\r\n" }) {
            return "\"" + text.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        return text
    }

    static let filePrefix = "mDNSShark-ble-advertisements-"
    /// Exports stay encrypted while the phone is locked.
    static let writeOptions: Data.WritingOptions = [.atomic, .completeFileProtection]

    static func fileStem(now: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd-HHmmss"
        return "\(filePrefix)\(formatter.string(from: now))"
    }

    /// Removes exports a share sheet never cleaned up, for example when the app was closed mid-share.
    @discardableResult
    static func purgeStaleExports(in directory: URL = FileManager.default.temporaryDirectory) -> Int {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: directory.path) else { return 0 }
        var removed = 0
        for name in names where name.hasPrefix(filePrefix) {
            if (try? fm.removeItem(at: directory.appendingPathComponent(name))) != nil { removed += 1 }
        }
        return removed
    }

    private static func isoFormatter() -> ISO8601DateFormatter {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }
}
