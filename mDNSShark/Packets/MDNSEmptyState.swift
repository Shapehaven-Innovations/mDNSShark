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
        if let name = interfaceName(from: listenerStatus) {
            return "Listening for mDNS on \(name). Open a Bonjour app on another device to generate traffic."
        }
        if listenerStatus.isEmpty {
            return "Waiting for the mDNS listener to report its status."
        }
        return "mDNS listener could not start (\(listenerStatus))."
    }

    /// "listening on en0 (ifindex 13)" -> "en0"; nil for any other status.
    static func interfaceName(from status: String) -> String? {
        let prefix = "listening on "
        guard status.hasPrefix(prefix) else { return nil }
        let rest = status.dropFirst(prefix.count)
        let name = rest.prefix { !$0.isWhitespace }
        return name.isEmpty ? nil : String(name)
    }
}
