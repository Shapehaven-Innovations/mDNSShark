import Foundation

/// Bluetooth service UUID names, parsed from `UUID<TAB>name` lines.
/// Pure except `bundled`, the one place that reads the package bundle.
public struct BLEServiceNameTable: Sendable {
    private let names: [String: String]

    public init(text: String) {
        var result: [String: String] = [:]
        for line in text.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: "\t", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }
            let name = parts[1].trimmingCharacters(in: .whitespaces)
            let key = Self.shortForm(parts[0].trimmingCharacters(in: .whitespaces))
            if !key.isEmpty, !name.isEmpty { result[key] = name }
        }
        names = result
    }

    public func name(forUUID uuid: String) -> String? { names[Self.shortForm(uuid)] }

    /// Uppercases and collapses the Bluetooth base UUID form to its 4 digit short form.
    public static func shortForm(_ uuid: String) -> String {
        let upper = uuid.uppercased()
        let suffix = "-0000-1000-8000-00805F9B34FB"
        if upper.count == 36, upper.hasPrefix("0000"), upper.hasSuffix(suffix) {
            return String(upper.dropFirst(4).prefix(4))
        }
        return upper
    }

    /// Empty when the resource is missing; never crashes.
    public static let bundled: BLEServiceNameTable = {
        guard let url = Bundle.module.url(forResource: "bluetooth-service-uuids", withExtension: "txt"),
              let text = try? String(contentsOf: url, encoding: .utf8) else { return BLEServiceNameTable(text: "") }
        return BLEServiceNameTable(text: text)
    }()
}
