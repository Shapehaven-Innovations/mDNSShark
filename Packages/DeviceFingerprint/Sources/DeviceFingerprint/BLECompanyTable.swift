import Foundation

/// Bluetooth SIG company identifiers, parsed from `decimalCode<TAB>name` lines.
/// Pure except `bundled`, the one place that reads the package bundle.
public struct BLECompanyTable: Sendable {
    private let names: [UInt16: String]

    public init(text: String) { names = Self.parse(text) }

    public static func parse(_ text: String) -> [UInt16: String] {
        var result: [UInt16: String] = [:]
        for line in text.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: "\t", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2,
                  let code = UInt16(parts[0].trimmingCharacters(in: .whitespaces)) else { continue }
            let name = parts[1].trimmingCharacters(in: .whitespaces)
            if !name.isEmpty { result[code] = name }
        }
        return result
    }

    public func name(for code: UInt16) -> String? { names[code] }

    /// Empty when the resource is missing; never crashes.
    public static let bundled: BLECompanyTable = {
        guard let url = Bundle.module.url(forResource: "bluetooth-company-ids", withExtension: "txt"),
              let text = try? String(contentsOf: url, encoding: .utf8) else { return BLECompanyTable(text: "") }
        return BLECompanyTable(text: text)
    }()
}
