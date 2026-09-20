import Foundation
import DeviceFingerprint
import os

/// Tries Linksys JNAP first (`POST /JNAP/`, JSON), then falls back to HNAP
/// (`POST /HNAP1/`, SOAP/XML) if JNAP doesn't answer. JNAP covers newer
/// Linksys hardware (Velop mesh included); HNAP covers older Linksys and
/// some D-Link. Both are the device answering its own vendor API directly —
/// same ground-truth tier as `UbiquitiDiscoveryProbe`/`ASUSDiscoveryProbe`,
/// not a guess.
///
/// Mirrors `SSDPDescriptionFetcher`'s LAN-only discipline: `ip` here is
/// always a literal address from the local subnet scan (never a URL header),
/// but the same `isLANLocalAddress` guard is applied for defense in depth —
/// every enrichment path validates its own target before sending.
final class JNAPHNAPProbe {
    private let logger = Logger(subsystem: "com.mDNSShark", category: "JNAPHNAPProbe")

    func probe(ip: String, timeout: TimeInterval) async -> JNAPHNAPInfo? {
        guard SSDPDescriptionFetcher.isLANLocalAddress(ip) else {
            logger.debug("JNAPHNAPProbe: refusing non-LAN-local ip \(ip, privacy: .public)")
            return nil
        }
        // IPv4 only for now: URL(string:) needs an IPv6 host bracketed
        // ("http://[fe80::1]/...") and a zone id stripped first, which
        // isLANLocalAddress's own IPv6 support doesn't handle end-to-end
        // yet. Rejecting explicitly here (rather than letting the URL
        // fail to construct silently) keeps this an informed limitation,
        // not a silent no-op — the UDP probes make the same IPv4-only
        // call via inet_pton(AF_INET).
        guard !ip.contains(":") else {
            logger.debug("JNAPHNAPProbe: IPv6 not yet supported, skipping \(ip, privacy: .public)")
            return nil
        }
        if let info = await fetchJNAP(ip: ip, timeout: timeout) {
            return info
        }
        guard !Task.isCancelled else { return nil }
        return await fetchHNAP(ip: ip, timeout: timeout)
    }

    private func fetchJNAP(ip: String, timeout: TimeInterval) async -> JNAPHNAPInfo? {
        guard let url = URL(string: "http://\(ip)/JNAP/") else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = timeout
        request.setValue("http://linksys.com/jnap/core/GetDeviceInfo", forHTTPHeaderField: "X-JNAP-Action")
        request.setValue("application/json; charset=UTF-8", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data("{}".utf8)
        do {
            let (data, response) = try await URLSession.shared.data(for: request, delegate: RedirectBlockingDelegate())
            guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
                return nil
            }
            return JNAPHNAPParser.parseJNAP(data)
        } catch {
            logger.debug("JNAPHNAPProbe: JNAP fetch failed for \(ip, privacy: .public): \(error.localizedDescription)")
            return nil
        }
    }

    private func fetchHNAP(ip: String, timeout: TimeInterval) async -> JNAPHNAPInfo? {
        guard let url = URL(string: "http://\(ip)/HNAP1/") else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = timeout
        request.setValue("\"http://purenetworks.com/HNAP1/GetDeviceSettings\"", forHTTPHeaderField: "SOAPAction")
        request.setValue("text/xml; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data("""
        <?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
        <GetDeviceSettings xmlns="http://purenetworks.com/HNAP1/" />
        </soap:Body>
        </soap:Envelope>
        """.utf8)
        do {
            let (data, response) = try await URLSession.shared.data(for: request, delegate: RedirectBlockingDelegate())
            guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
                return nil
            }
            return JNAPHNAPParser.parseHNAP(data)
        } catch {
            logger.debug("JNAPHNAPProbe: HNAP fetch failed for \(ip, privacy: .public): \(error.localizedDescription)")
            return nil
        }
    }

    /// Blocks all HTTP redirects, same reasoning as `SSDPDescriptionFetcher`'s
    /// own delegate — a LAN-local target must not be able to redirect the
    /// request off-LAN.
    private final class RedirectBlockingDelegate: NSObject, URLSessionTaskDelegate {
        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
            completionHandler(nil)
        }
    }
}
