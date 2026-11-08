import Foundation

/// Reads the Matter commissionable node discovery TXT key `VP` ("<vendor>+<product>" or "<vendor>", decimal).
public enum MatterTXT {
    public static func vendorProduct(_ txt: [String: String]) -> (vendorID: UInt16, productID: UInt16?)? {
        guard let raw = txt["VP"]?.trimmingCharacters(in: .whitespaces), !raw.isEmpty else { return nil }
        let parts = raw.split(separator: "+", maxSplits: 1, omittingEmptySubsequences: false)
        guard let first = parts.first, let vendor = decimal(first) else { return nil }
        if parts.count == 2 {
            guard let product = decimal(parts[1]) else { return nil }
            return (vendor, product)
        }
        return (vendor, nil)
    }

    /// ASCII digits only, so a sign or a non-ASCII digit never parses.
    private static func decimal(_ s: Substring) -> UInt16? {
        guard !s.isEmpty, s.utf8.allSatisfy({ (0x30...0x39).contains($0) }) else { return nil }
        return UInt16(s)
    }
}
