import Foundation

/// Loads a `prefix<TAB>vendor` text table (24-bit OUI prefixes only — MA-M/MA-S
/// sub-allocations with a `/nn` suffix are out of scope for this lookup) and
/// answers manufacturer-by-MAC-prefix queries. Pure — no I/O, no Foundation
/// bundle access, so it's fully unit-testable without touching disk.
public struct OUIDataset {
    private let table: [String: String]

    public init(text: String) {
        self.table = Self.parse(text)
    }

    public static func parse(_ text: String) -> [String: String] {
        var result: [String: String] = [:]
        for line in text.split(separator: "\n") {
            let parts = line.split(separator: "\t", maxSplits: 1)
            guard parts.count == 2 else { continue }
            let prefix = Self.normalize(String(parts[0]))
            guard prefix.count == 6 else { continue }
            result[prefix] = String(parts[1])
        }
        return result
    }

    public func manufacturer(for oui: String) -> String? {
        table[Self.normalize(oui)]
    }

    private static func normalize(_ raw: String) -> String {
        raw.lowercased().filter { $0.isHexDigit }.prefix(6).description
    }
}
