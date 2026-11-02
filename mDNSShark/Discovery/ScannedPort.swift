//
//  ScannedPort.swift
//  mDNSShark
//
//  Created by user on 4/7/25.
//


//
//  PortScannerView.swift
//  mDNSShark
//
//  Created by user on 4/5/25.
//  Updated for configurable timeout and banner retrieval per port.
//  Feature: TCP port scanner that identifies devices on the user's own network
//

import SwiftUI
import Network
import Security
import DeviceFingerprint

// Represents an open port and, if available, its banner.
struct ScannedPort: Identifiable {
    var id: Int { port }
    let port: Int
    let banner: String?
    /// The `Location` of a redirect answer from an HTTP port, as received.
    var redirectLocation: String? = nil
}

// A simple port scanner that uses NWConnection to check TCP ports and grab banner info.
class PortScanner {
    // A helper class to ensure a single completion for each connection.
    class Flag {
        private var completed = false
        private let queue = DispatchQueue(label: "FlagQueue")

        // Returns true only the first time it's called.
        func setCompleted() -> Bool {
            return queue.sync {
                if !completed {
                    completed = true
                    return true
                }
                return false
            }
        }
    }

    // Thread-safe latch recording whether a connection ever reached `.ready`.
    // Written from the connection's stateUpdateHandler callback context, read
    // from the timeout closure's context; those can run concurrently, hence
    // the same serial-queue-guarded pattern as `Flag`.
    private class ReadyTracker {
        private var ready = false
        private let queue = DispatchQueue(label: "ReadyTrackerQueue")

        func markReady() {
            queue.sync { ready = true }
        }

        func wasReady() -> Bool {
            queue.sync { ready }
        }
    }
    
    /// Ports worth checking specifically because they're where UniFi gear
    /// and common LAN devices expose identifying services: 22 SSH, 80/443
    /// HTTP(S), 8080/8443 UniFi inform/classic-controller, 23 telnet, 6789
    /// UniFi speed test, 7442/7447 UniFi Protect, and 53 DNS, which nearly
    /// every router and hotspot answers even when it filters everything else.
    static let uniFiRelevantPorts = [22, 80, 443, 8080, 8443, 23, 6789, 7442, 7447, 53]

    /// Camera ports scanned on every on-subnet host: 554 RTSP gets one OPTIONS request, and 8000 is only listened on.
    static let cameraProbePorts = [554, 8000]

    /// The ports for one host: the always set, plus the connect-only camera ports (no bytes written) only when the host already
    /// looks like a camera. Every other host is never scanned on those ports.
    static func ports(cameraHint: Bool) -> [Int] {
        uniFiRelevantPorts + cameraProbePorts + (cameraHint ? CameraPortBanner.connectOnlyPorts : [])
    }

    private let rtspPort: Int
    private let hikvisionControlPort: Int
    private let connectOnlyPorts: Set<Int>

    /// The defaults are the production ports; tests pass loopback ports so no fixed port is ever bound.
    init(rtspPort: Int = 554, hikvisionControlPort: Int = 8000, connectOnlyPorts: Set<Int> = Set(CameraPortBanner.connectOnlyPorts)) {
        self.rtspPort = rtspPort
        self.hikvisionControlPort = hikvisionControlPort
        self.connectOnlyPorts = connectOnlyPorts
    }

    /// Banner for a port that speaks first. The control port is matched on the raw bytes before any String conversion.
    func listenBanner(port: Int, data: Data?) -> String? {
        guard let data, !data.isEmpty else { return nil }
        if port == hikvisionControlPort, let label = CameraPortBanner.label(port8000: data) { return label }
        return String(data: data, encoding: .utf8)
    }

    /// The RTSP reply as literal banner text; a reply that is not RTSP falls back to its decoded bytes.
    static func rtspBanner(from data: Data?) -> String? {
        guard let data, !data.isEmpty else { return nil }
        if let reply = RTSPReply.parse(data) { return reply.bannerText }
        return String(data: data.prefix(RTSPReply.maxParsedBytes), encoding: .utf8)
    }

    /// Plaintext-HTTP-shaped ports: we speak the request, plaintext TCP.
    private static let httpPlainPorts: Set<Int> = [80, 8080]
    /// HTTPS-shaped ports: same request, but over a TLS session.
    private static let httpTLSPorts: Set<Int> = [443, 8443]
    /// Union of the above: every port for which we actively send a
    /// request instead of just listening for the remote side to speak
    /// first. Deliberately excludes 22/23/6789/7442/7447: SSH/telnet speak
    /// first on their own, and the UniFi-specific ports (6789/7442/7447)
    /// use an unknown/proprietary protocol that isn't safe to guess at.
    private static var httpShapedPorts: Set<Int> { httpPlainPorts.union(httpTLSPorts) }

    /// Builds the `NWParameters` for one port: plain TCP for everything
    /// except the HTTPS-shaped ports, which need an actual TLS handshake
    /// before an HTTP request means anything.
    private static func connectionParameters(for port: Int, ip: String) -> NWParameters {
        guard httpTLSPorts.contains(port) else { return .tcp }

        // Defense in depth: this method's only current caller (`scan`) is
        // only ever reached via DeviceEnrichmentCoordinator.enrich, which
        // already refuses a non-LAN-local `ip` before firing any probe,
        // but the certificate-validation bypass below is dangerous enough
        // that it shouldn't depend on staying correct-by-convention at a
        // call site two files away. If `ip` isn't LAN-local, skip the
        // bypass entirely and fall back to NWProtocolTLS's default
        // (verifying) options, so a future caller that forgets the
        // upstream gate fails safe instead of silently trusting an
        // arbitrary certificate from off-LAN.
        guard SSDPDescriptionFetcher.isLANLocalAddress(ip) else {
            return NWParameters(tls: NWProtocolTLS.Options())
        }

        let tlsOptions = NWProtocolTLS.Options()
        // Certificate validation is intentionally disabled here. This is a
        // LAN-only banner-grab against a device the user explicitly chose
        // to scan; the goal is only "read back whatever this admin UI
        // sends", not to establish a trusted channel. Router/IoT admin
        // HTTPS UIs are overwhelmingly self-signed, so verifying the chain
        // would just make this fail against almost every real target. This
        // is not a trust decision about the connection's data (nothing
        // downstream treats the response as authenticated), so skipping
        // verification here does not weaken anything else in the app.
        sec_protocol_options_set_verify_block(
            tlsOptions.securityProtocolOptions,
            { _, _, complete in complete(true) },
            DispatchQueue.global(qos: .userInitiated)
        )

        // Accept TLS 1.2, the minimum SecProtocolTypes still supports
        // (TLSv10/TLSv11 were deprecated in iOS 15) — many embedded/router
        // TLS-1.2-only stacks would otherwise fail the handshake and get
        // silently dropped from openPorts as "closed" by scan()'s
        // .failed/.waiting branch. TLS-1.0/1.1-only devices stay unsupported.
        sec_protocol_options_set_min_tls_protocol_version(
            tlsOptions.securityProtocolOptions,
            .TLSv12
        )

        return NWParameters(tls: tlsOptions)
    }

    /// Turns whatever bytes came back from an HTTP-shaped port into a
    /// banner string for `guessFromBanner`'s substring matching. Leads with
    /// the parsed Server/Title/WWW-Authenticate realm (readable, and often
    /// the whole answer), only widening to the full raw page body when
    /// that narrow text alone doesn't already identify a manufacturer or
    /// OS. Blending in the raw body unconditionally would widen every
    /// vendor substring check (including risky ones like a bare "asus") to
    /// arbitrary page content (a JS bundle URL, ad script, or footer text
    /// that happens to contain a vendor's name) for every device, not just
    /// the ones that actually need it. Confirmed on real hardware: a
    /// GL.iNet GL-MT6000 reports a fully generic `Server: nginx/1.26.1` and
    /// `<title>Admin Panel</title>` (narrow guess finds nothing), with its
    /// only identifying string ("gl-ui", GL.iNet's own admin-UI product
    /// name) sitting in the body's `<noscript>` fallback text.
    private static func httpBannerString(from data: Data?) -> String? {
        guard let data, !data.isEmpty else { return nil }
        let raw = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1)
        guard let info = HTTPBannerParser.parse(data) else { return raw }

        var parts: [String] = []
        if let server = info.server { parts.append("Server: \(server)") }
        if let title = info.title { parts.append("Title: \(title)") }
        if let realm = info.authRealm { parts.append("Realm: \(realm)") }
        guard !parts.isEmpty else { return raw }

        let narrow = parts.joined(separator: " | ")
        let narrowGuess = guessFromBanner(narrow)
        if narrowGuess.manufacturer == nil, narrowGuess.os == nil, let raw {
            return narrow + " | " + raw
        }
        return narrow
    }

    /// Scans an explicit, possibly non-contiguous, set of ports on one host
    /// and calls `completion` once with everything found open (with banners
    /// where grabbable). Meant for programmatic per-IP calls from
    /// DeviceEnrichmentCoordinator, one `PortScanner` instance per call.
    func scan(ip: String, ports: [Int], timeout: TimeInterval, completion: @escaping ([ScannedPort]) -> Void) {
        var results: [ScannedPort] = []
        let resultsQueue = DispatchQueue(label: "PortScanner.results")
        let group = DispatchGroup()
        let queue = DispatchQueue.global(qos: .userInitiated)

        for port in ports {
            group.enter()
            let nwPort = NWEndpoint.Port(integerLiteral: NWEndpoint.Port.IntegerLiteralType(port))
            let parameters = PortScanner.connectionParameters(for: port, ip: ip)
            let connection = NWConnection(host: NWEndpoint.Host(ip), port: nwPort, using: parameters)
            let flag = Flag()
            let readyTracker = ReadyTracker()
            let isHTTPShaped = PortScanner.httpShapedPorts.contains(port)
            let isConnectOnly = connectOnlyPorts.contains(port)
            let isRTSP = port == rtspPort

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    // Do NOT consume `flag` here. For the receive-only ports
                    // below (SSH/telnet/UniFi-inform), the remote side may
                    // never send anything unprompted. For the HTTP-shaped
                    // ports we do send a request, but a send failure or a
                    // response that simply never arrives means `receive`'s
                    // completion can still never fire. Either way,
                    // consuming the flag now would starve the timeout
                    // closure below of its only chance to ever resolve this
                    // port.
                    readyTracker.markReady()

                    if isConnectOnly {
                        // Presence only: nothing is written or read, so the open port is recorded and the connection closed.
                        guard flag.setCompleted() else { return }
                        resultsQueue.sync { results.append(ScannedPort(port: port, banner: nil)) }
                        connection.cancel()
                        group.leave()
                    } else if isRTSP {
                        // The only bytes ever sent to an RTSP port: one OPTIONS request, then a bounded read.
                        connection.send(content: RTSPReply.optionsRequest(ip: ip, port: port), completion: .contentProcessed { _ in
                            connection.receive(minimumIncompleteLength: 1, maximumLength: RTSPReply.maxParsedBytes) { data, _, _, _ in
                                guard flag.setCompleted() else { return }
                                let banner = PortScanner.rtspBanner(from: data)
                                resultsQueue.sync { results.append(ScannedPort(port: port, banner: banner)) }
                                connection.cancel()
                                group.leave()
                            }
                        })
                    } else if isHTTPShaped {
                        // HTTP servers wait for the client to speak first;
                        // unlike SSH/telnet below, nothing arrives here
                        // unprompted, so send a minimal GET before reading.
                        let request = "GET / HTTP/1.1\r\nHost: \(ip)\r\nConnection: close\r\n\r\n"
                        connection.send(content: Data(request.utf8), completion: .contentProcessed { _ in
                            // Proceed to receive regardless of send outcome:
                            // a send error just means the read below will
                            // most likely time out with no data, which the
                            // timeout closure already handles via
                            // `readyTracker`.
                            connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { data, _, _, _ in
                                guard flag.setCompleted() else { return }
                                let banner = PortScanner.httpBannerString(from: data)
                                let redirect = data.flatMap { HTTPBannerParser.redirectLocation($0) }
                                resultsQueue.sync { results.append(ScannedPort(port: port, banner: banner, redirectLocation: redirect)) }
                                connection.cancel()
                                group.leave()
                            }
                        })
                    } else {
                        connection.receive(minimumIncompleteLength: 1, maximumLength: 256) { data, _, _, _ in
                            guard flag.setCompleted() else { return }
                            let banner = self.listenBanner(port: port, data: data)
                            resultsQueue.sync { results.append(ScannedPort(port: port, banner: banner)) }
                            connection.cancel()
                            group.leave()
                        }
                    }
                case .failed, .waiting:
                    // NWConnection reports a LAN connection-refused as
                    // `.waiting(error)`, not `.failed`; treat both as a
                    // closed port and resolve immediately rather than
                    // burning the full per-port timeout.
                    //
                    // Known, accepted trade-off for 443/8443: a connection
                    // whose TCP handshake succeeded but whose TLS handshake
                    // then failed also lands here as `.failed(.tls(...))`
                    // and gets treated identically to a genuinely closed
                    // port, even though it was TCP-reachable. See the
                    // TLS-min-version comment in connectionParameters(for:)
                    // for why this is intentionally not fixed here.
                    if flag.setCompleted() { connection.cancel(); group.leave() }
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) {
                if flag.setCompleted() {
                    // The port accepted a connection but never spoke first;
                    // still record it as open (banner: nil) rather than
                    // silently dropping it. This confirms, for example, a web UI on 443
                    // even without a grabbable banner.
                    if readyTracker.wasReady() {
                        resultsQueue.sync { results.append(ScannedPort(port: port, banner: nil)) }
                    }
                    connection.cancel()
                    group.leave()
                }
            }
        }

        group.notify(queue: .main) {
            resultsQueue.sync { completion(results) }
        }
    }
}

