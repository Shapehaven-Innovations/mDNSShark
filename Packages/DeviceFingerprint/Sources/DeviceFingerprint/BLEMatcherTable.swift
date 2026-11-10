import Foundation

/// Product matchers generated from Home Assistant's Bluetooth matchers (see scripts/update_ble_data.py).
/// One line per matcher: `label<TAB>kind<TAB>conditions`, conditions space separated and all required:
/// `mfr=<decimal company id>`, `start=<hex bytes the manufacturer payload begins with>`, `svc=<service UUID>`, `svcdata=<UUID>`.
public struct BLEMatcherTable: Sendable {
    struct Matcher: Sendable {
        var label: String
        var kind: BLEKind
        var company: UInt16?
        var start: [UInt8]
        var service: String?
        var serviceData: String?
    }

    private let matchers: [Matcher]

    public init(text: String) {
        var result: [Matcher] = []
        for line in text.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: "\t", omittingEmptySubsequences: false)
            guard parts.count == 3, let kind = BLEKind(rawValue: String(parts[1])) else { continue }
            var m = Matcher(label: String(parts[0]), kind: kind, company: nil, start: [], service: nil, serviceData: nil)
            for condition in parts[2].split(separator: " ") {
                let pair = condition.split(separator: "=", maxSplits: 1)
                guard pair.count == 2 else { continue }
                switch pair[0] {
                case "mfr": m.company = UInt16(pair[1])
                case "start": m.start = Self.bytes(String(pair[1]))
                case "svc": m.service = BLEServiceNameTable.shortForm(String(pair[1]))
                case "svcdata": m.serviceData = BLEServiceNameTable.shortForm(String(pair[1]))
                default: break
                }
            }
            result.append(m)
        }
        matchers = result
    }

    private static func bytes(_ hex: String) -> [UInt8] {
        var out: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex, let next = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) {
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return [] }
            out.append(byte)
            index = next
        }
        return out
    }

    /// The first matcher whose every condition holds; the file lists the most specific matchers first.
    public func match(companyID: UInt16?, manufacturerPayload: [UInt8], keys: Set<String>, serviceDataKeys: Set<String>) -> (label: String, kind: BLEKind)? {
        for m in matchers {
            if let company = m.company, company != companyID { continue }
            if !m.start.isEmpty, !manufacturerPayload.starts(with: m.start) { continue }
            if let service = m.service, !keys.contains(service) { continue }
            if let data = m.serviceData, !serviceDataKeys.contains(data) { continue }
            return (m.label, m.kind)
        }
        return nil
    }

    /// Empty when the resource is missing; never crashes.
    public static let bundled: BLEMatcherTable = {
        guard let url = Bundle.module.url(forResource: "ble-matchers", withExtension: "txt"),
              let text = try? String(contentsOf: url, encoding: .utf8) else { return BLEMatcherTable(text: "") }
        return BLEMatcherTable(text: text)
    }()
}
