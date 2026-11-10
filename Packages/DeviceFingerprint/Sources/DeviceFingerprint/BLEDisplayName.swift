import Foundation

/// Cleans an advertised name before it is shown or stored.
public enum BLEDisplayName {
    public static let maxLength = 64
    public static let unnamed = "Unnamed"

    /// Drops control and format scalars (bidi marks, zero width), collapses whitespace, trims and truncates to 64 scalars.
    public static func sanitized(_ raw: String?) -> String? {
        guard let raw else { return nil }
        var scalars = String.UnicodeScalarView()
        for scalar in raw.unicodeScalars {
            if scalar.properties.isWhitespace {
                scalars.append(" ")
            } else if scalar.properties.generalCategory != .control, scalar.properties.generalCategory != .format {
                scalars.append(scalar)
            }
        }
        let collapsed = String(scalars).split(separator: " ", omittingEmptySubsequences: true).joined(separator: " ")
        var result = String(String.UnicodeScalarView(collapsed.unicodeScalars.prefix(maxLength)))
        while result.hasSuffix(" ") { result.removeLast() }
        return result.isEmpty ? nil : result
    }

    /// The row title when nothing advertises a name: "Samsung device", "Apple Earbuds", else "Unnamed".
    public static func fallbackTitle(company: String?, typeLabel: String, isTyped: Bool) -> String {
        guard let short = company.flatMap(shortCompany) else {
            return isTyped ? "\(unnamed) \(typeLabel)" : unnamed
        }
        return "\(short) \(isTyped ? typeLabel : "device")"
    }

    private static let legalSuffixes: Set<String> = ["inc", "ltd", "llc", "co", "corp", "corporation", "gmbh", "limited", "ag", "ab", "bv", "sa", "plc", "kg", "oy"]

    /// A company name without legal suffixes, for the fallback title only. The literal name stays in the subtitle.
    public static func shortCompany(_ name: String) -> String? {
        var words = name.split(separator: " ").map(String.init)
        func trimmed(_ s: String) -> String { String(s.drop { ",. ".contains($0) }.reversed().drop { ",. ".contains($0) }.reversed()) }
        while words.count > 1 {
            let last = trimmed(words[words.count - 1]).lowercased()
            if legalSuffixes.contains(last) || last.isEmpty { words.removeLast() } else { break }
        }
        let result = trimmed(words.joined(separator: " "))
        return result.isEmpty ? nil : result
    }
}
