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
}
