// mDNSShark/Packets/MDNSEmptyState.swift
import Foundation

/// Text under the mDNS chip when it has no rows, chosen from capture state, the mDNS filter and the extension's listener status.
enum MDNSEmptyState {
    static func text(isCapturing: Bool, filterOn: Bool, listenerStatus: String) -> String {
        guard isCapturing else {
            return "Tap Start to begin capturing. mDNS is received by a listener in the capture extension on 224.0.0.251:5353 and written to the same pcap."
        }
        guard filterOn else {
            return "mDNS capture is turned off in Settings > Capture Filters."
        }
        let names = interfaceNames(from: listenerStatus)
        if !names.isEmpty {
            return "Listening for mDNS on \(joined(names)). Open a Bonjour app on another device to generate traffic."
        }
        if listenerStatus.isEmpty {
            return "Waiting for the mDNS listener to report its status."
        }
        return "mDNS listener could not start (\(listenerStatus))."
    }

    /// "listening on en0 (ifindex 13)" -> "en0"; the first interface, nil for any other status.
    static func interfaceName(from status: String) -> String? {
        interfaceNames(from: status).first
    }

    /// "listening on en0 (ifindex 13), bridge100 (ifindex 20); en3 failed: ..." -> ["en0", "bridge100"]; empty for any other status.
    static func interfaceNames(from status: String) -> [String] {
        let prefix = "listening on "
        guard status.hasPrefix(prefix) else { return [] }
        let list = status.dropFirst(prefix.count).split(separator: ";", maxSplits: 1).first ?? ""
        return list.split(separator: ",").compactMap { entry in
            let name = entry.drop { $0.isWhitespace }.prefix { !$0.isWhitespace }
            // ", IPv6 only" is a qualifier, not an interface.
            return name.isEmpty || name == "IPv6" ? nil : String(name)
        }
    }

    /// "en0", "en0 and bridge100", "en0, en3 and bridge100".
    private static func joined(_ names: [String]) -> String {
        guard names.count > 1 else { return names.first ?? "" }
        return names.dropLast().joined(separator: ", ") + " and " + names[names.count - 1]
    }
}
