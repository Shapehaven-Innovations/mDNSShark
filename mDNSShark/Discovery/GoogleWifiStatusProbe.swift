import Foundation
import DeviceFingerprint
import os

/// Fetches a Google Wifi / Nest Wifi router's local status API
/// (`GET /api/v1/status`, unauthenticated, no request body). The device
/// answering its own status endpoint directly — ground-truth tier, not a
/// guess.
///
/// Unlike the other probes, this one is only ever dispatched for a host
/// `NetworkScanViewModel` already flagged as Google Cast-capable via mDNS
/// (`_googlecast._tcp`) — firing an active HTTP probe at every LAN host on
/// the chance it's a Google Wifi router would be exactly the kind of
/// speculative traffic this app's other probes avoid.
final class GoogleWifiStatusProbe {
    private let logger = Logger(subsystem: "com.mDNSShark", category: "GoogleWifiStatusProbe")

    func probe(ip: String, timeout: TimeInterval) async -> GoogleWifiStatusInfo? {
        guard SSDPDescriptionFetcher.isLANLocalAddress(ip) else {
            logger.debug("GoogleWifiStatusProbe: refusing non-LAN-local ip \(ip, privacy: .public)")
            return nil
        }
        // IPv4 only for now, same documented limitation as JNAPHNAPProbe.
        guard !ip.contains(":") else {
            logger.debug("GoogleWifiStatusProbe: IPv6 not yet supported, skipping \(ip, privacy: .public)")
            return nil
        }
        guard let url = URL(string: "http://\(ip)/api/v1/status") else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = timeout
        do {
            let (data, response) = try await URLSession.shared.data(for: request, delegate: LANRedirectBlockingDelegate())
            guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
                return nil
            }
            return GoogleWifiStatusParser.parse(data)
        } catch {
            logger.debug("GoogleWifiStatusProbe: fetch failed for \(ip, privacy: .public): \(error.localizedDescription)")
            return nil
        }
    }
}
