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
//  Feature: TCP Port Scanner for Penetration Testing
//

import SwiftUI
import Network

// Represents an open port and, if available, its banner.
struct ScannedPort: Identifiable {
    var id: Int { port }
    let port: Int
    let banner: String?
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
    // from the timeout closure's context — those can run concurrently, hence
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
    /// UniFi speed test, 7442/7447 UniFi Protect.
    static let uniFiRelevantPorts = [22, 80, 443, 8080, 8443, 23, 6789, 7442, 7447]

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
            let connection = NWConnection(host: NWEndpoint.Host(ip), port: nwPort, using: .tcp)
            let flag = Flag()
            let readyTracker = ReadyTracker()

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    // Do NOT consume `flag` here — a `.ready` connection that
                    // never sends unprompted data (most HTTP/TLS/UniFi-inform
                    // services) never fires `receive`'s completion, so
                    // consuming the flag now would starve the timeout closure
                    // below of its only chance to ever resolve this port.
                    readyTracker.markReady()
                    connection.receive(minimumIncompleteLength: 1, maximumLength: 256) { data, _, _, _ in
                        guard flag.setCompleted() else { return }
                        let banner = data.flatMap { $0.isEmpty ? nil : String(data: $0, encoding: .utf8) }
                        resultsQueue.sync { results.append(ScannedPort(port: port, banner: banner)) }
                        connection.cancel()
                        group.leave()
                    }
                case .failed, .waiting:
                    // NWConnection reports a LAN connection-refused as
                    // `.waiting(error)`, not `.failed` — treat both as a
                    // closed port and resolve immediately rather than
                    // burning the full per-port timeout.
                    if flag.setCompleted() { connection.cancel(); group.leave() }
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) {
                if flag.setCompleted() {
                    // The port accepted a connection but never spoke first;
                    // still record it as open (banner: nil) rather than
                    // silently dropping it — e.g. confirms a web UI on 443
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

