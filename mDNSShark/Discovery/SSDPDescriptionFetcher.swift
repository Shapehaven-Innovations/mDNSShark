import Foundation
import DeviceFingerprint
import os

/// Fetches the UPnP device-description document an SSDP `LOCATION` header
/// points to and parses it. LAN-local, so a short timeout is appropriate.
///
/// Privacy/security: this fetch must never leave the LAN. An SSDP
/// `LOCATION` header is attacker-controlled — any device on the LAN can send
/// an SSDP reply with an arbitrary `LOCATION` value, including one pointing
/// at a public-internet host — which would conflict with this app's "no
/// external servers involved" privacy claim. Before fetching we require the
/// URL's host to be a literal private/link-local/loopback IP address, and we
/// block HTTP redirects so a LAN-local starting URL can't redirect the
/// request somewhere external.
final class SSDPDescriptionFetcher {
    private let logger = Logger(subsystem: "com.mDNSShark", category: "SSDPDescriptionFetcher")

    func fetch(locationURL: URL, timeout: TimeInterval) async -> SSDPDescriptionInfo? {
        guard let host = locationURL.host, Self.isLANLocalAddress(host) else {
            logger.debug("SSDPDescriptionFetcher: refusing non-LAN-local LOCATION \(locationURL.absoluteString, privacy: .public)")
            return nil
        }

        var request = URLRequest(url: locationURL)
        request.timeoutInterval = timeout
        do {
            let (data, response) = try await URLSession.shared.data(for: request, delegate: LANRedirectBlockingDelegate())
            if let httpResponse = response as? HTTPURLResponse, !(200...299).contains(httpResponse.statusCode) {
                logger.debug("SSDPDescriptionFetcher: non-200 response (\(httpResponse.statusCode, privacy: .public)) for \(locationURL.absoluteString, privacy: .public)")
                return nil
            }
            return SSDPDeviceDescription.parse(data)
        } catch {
            logger.debug("SSDPDescriptionFetcher: fetch failed for \(locationURL.absoluteString, privacy: .public): \(error.localizedDescription)")
            return nil
        }
    }

    // MARK: - LAN-local validation

    /// True only if `host` is a literal IPv4/IPv6 address in a private,
    /// link-local, or loopback range:
    /// IPv4 — 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918),
    ///        169.254.0.0/16 (link-local), 127.0.0.0/8 (loopback).
    /// IPv6 — ::1 (loopback), fe80::/10 (link-local), fc00::/7 (unique local).
    ///
    /// A non-literal hostname is rejected rather than resolved: trusting a
    /// DNS lookup here would be subject to DNS rebinding (a hostname that
    /// resolves to a LAN address at validation time but an external one at
    /// connect time), and SSDP `LOCATION` values are IP literals in
    /// practice anyway.
    static func isLANLocalAddress(_ host: String) -> Bool {
        if let octets = parseIPv4(host) {
            let (a, b, _, _) = octets
            if a == 10 { return true }
            if a == 172, (16...31).contains(b) { return true }
            if a == 192, b == 168 { return true }
            if a == 169, b == 254 { return true }
            if a == 127 { return true }
            return false
        }
        if let bytes = parseIPv6(host) {
            if bytes == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] { return true } // ::1
            if bytes[0] == 0xfe, (bytes[1] & 0xc0) == 0x80 { return true } // fe80::/10
            if (bytes[0] & 0xfe) == 0xfc { return true } // fc00::/7
            return false
        }
        return false
    }

    private static func parseIPv4(_ host: String) -> (UInt8, UInt8, UInt8, UInt8)? {
        var addr = in_addr()
        guard host.withCString({ inet_pton(AF_INET, $0, &addr) }) == 1 else { return nil }
        let bytes = withUnsafeBytes(of: &addr.s_addr) { Array($0) }
        guard bytes.count == 4 else { return nil }
        return (bytes[0], bytes[1], bytes[2], bytes[3])
    }

    private static func parseIPv6(_ host: String) -> [UInt8]? {
        // Strip a zone id (e.g. "fe80::1%en0") which inet_pton rejects.
        let stripped = host.split(separator: "%", maxSplits: 1).first.map(String.init) ?? host
        var addr = in6_addr()
        guard stripped.withCString({ inet_pton(AF_INET6, $0, &addr) }) == 1 else { return nil }
        let bytes = withUnsafeBytes(of: &addr) { Array($0) }
        guard bytes.count == 16 else { return nil }
        return bytes
    }
}
