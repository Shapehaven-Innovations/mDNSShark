// mDNSShark/Discovery/DeviceEnrichmentCoordinator.swift
import Foundation
import Combine
import DeviceFingerprint
import os

/// Fans the seven active probes out per discovered IP, each gated by one
/// shared ProbeConcurrencyLimiter (global cap across every probe type and
/// every IP — never per-IP) and, for the UDP probes, one shared
/// UDPSendPacer (minimum spacing between sends). Publishes each IP's
/// collected DeviceEnrichment results as they complete; NetworkScanViewModel
/// folds them into the matching DiscoveredDevice via DeviceFingerprint.merge.
///
/// Marked `@MainActor` because its only caller (`NetworkScanViewModel`) is
/// itself MainActor-isolated, and because `activeTasks` (the in-flight-task
/// tracking `cancelAll()` needs) has to live in one consistent isolation
/// domain to be mutated safely both from `enrich`/`enrichDescription`
/// (synchronous calls from the view model) and from each task's own cleanup
/// when it finishes. This does not push actual network I/O onto the main
/// thread — the probe types themselves (`UbiquitiDiscoveryProbe`,
/// `NetBIOSProbe`, etc.) are plain, non-isolated classes, so their socket
/// work still runs off the main actor; only the thin orchestration here is
/// main-actor-isolated.
@MainActor
final class DeviceEnrichmentCoordinator {
    let results = PassthroughSubject<(ip: String, enrichments: [DeviceEnrichment]), Never>()

    private let limiter = ProbeConcurrencyLimiter(maxConcurrent: 32)
    private let udpPacer = UDPSendPacer(minimumSpacing: .milliseconds(15))

    private let ubiquitiProbe = UbiquitiDiscoveryProbe()
    private let asusProbe = ASUSDiscoveryProbe()
    private let jnapHnapProbe = JNAPHNAPProbe()
    private let netBIOSProbe = NetBIOSProbe()
    private let ttlProbe = TTLProbe()
    private let ssdpFetcher = SSDPDescriptionFetcher()
    private let logger = Logger(subsystem: "com.mDNSShark", category: "DeviceEnrichmentCoordinator")

    private let probeTimeout: TimeInterval = 1.5
    private let fetchTimeout: TimeInterval = 2.5
    private let portScanTimeout: TimeInterval = 1.0
    /// Per-attempt budget for JNAPHNAPProbe's JNAP try and its HNAP
    /// fallback — worst case (neither answers) holds the limiter slot for
    /// roughly 2x this, same order as fetchTimeout.
    private let jnapHnapAttemptTimeout: TimeInterval = 1.0

    /// In-flight `enrich`/`enrichDescription` tasks, keyed by a locally
    /// generated id so each task can remove itself when it finishes without
    /// relying on `Task` being storable in a `Set` by identity. `cancelAll()`
    /// cancels and clears everything still running — called whenever a
    /// fresh scan starts so a previous scan's still-running probes can never
    /// race or deliver results into the new scan's state.
    private var activeTasks: [UUID: Task<Void, Never>] = [:]

    /// Fire all seven probes for one IP concurrently and publish the combined
    /// results once every probe has either answered or timed out. Safe to
    /// call many times concurrently for different IPs — the shared limiter
    /// is what keeps total outbound traffic bounded, not caller discipline.
    ///
    /// Guarded at the top by the same LAN-local check `SSDPDescriptionFetcher`
    /// applies to its own fetch: `ip` here can originate from an
    /// attacker-controlled SSDP LOCATION header or an mDNS-resolved hostname,
    /// and every one of the seven probes below (including PortScanner's
    /// NWConnection, which accepts a hostname and would trigger a DNS
    /// lookup) must never fire against an address outside the
    /// private/link-local/loopback ranges — this is the single choke point
    /// every enrichment path goes through. `JNAPHNAPProbe` applies the same
    /// guard again internally since it targets `ip` directly rather than
    /// going through this call site.
    func enrich(ip: String, locationURL: URL?) {
        guard SSDPDescriptionFetcher.isLANLocalAddress(ip) else {
            logger.debug("enrich: refusing non-LAN-local ip \(ip, privacy: .public)")
            return
        }
        let taskID = UUID()
        let task = Task {
            async let ubiquiti = limitedUbiquitiProbe(ip: ip)
            async let asus = limitedASUSProbe(ip: ip)
            async let jnapHnap = limitedJNAPHNAPProbe(ip: ip)
            async let netbios = limitedNetBIOSProbe(ip: ip)
            async let ttl = limitedTTLProbe(ip: ip)
            async let ssdp = limitedSSDPFetch(locationURL: locationURL)
            async let ports = limitedPortScan(ip: ip)

            var enrichments: [DeviceEnrichment] = []
            if let r = await ubiquiti {
                enrichments.append(DeviceEnrichment(mac: r.mac, manufacturer: "Ubiquiti Networks Inc.",
                                                     inferredOS: r.model.map { "UniFi (\($0))" } ?? "UniFi OS",
                                                     openPorts: [], source: .ubiquitiDiscovery))
            }
            if let r = await asus {
                enrichments.append(DeviceEnrichment(mac: r.mac, manufacturer: "ASUS",
                                                     inferredOS: r.model.map { "ASUS (\($0))" },
                                                     openPorts: [], source: .asusDiscovery))
            }
            if let r = await jnapHnap {
                // Unlike UbiquitiDiscoveryProbe/ASUSDiscoveryProbe, this
                // probe covers multiple vendors (Linksys, D-Link), so the
                // vendor prefix comes from the reply itself, not a literal.
                let label = r.modelName.map { m in r.vendorName.map { "\($0) \(m)" } ?? m }
                enrichments.append(DeviceEnrichment(mac: nil, manufacturer: r.vendorName,
                                                     inferredOS: label.map { l in r.firmwareVersion.map { "\(l) (\($0))" } ?? l },
                                                     openPorts: [], source: .jnapHnapDiscovery))
            }
            if let r = await netbios, let mac = r.mac {
                enrichments.append(DeviceEnrichment(mac: mac, manufacturer: OUIDatabase.shared.manufacturer(for: mac), inferredOS: nil,
                                                     openPorts: [], source: .ouiLookup))
            }
            if let os = await ttl {
                enrichments.append(DeviceEnrichment(mac: nil, manufacturer: nil, inferredOS: os,
                                                     openPorts: [], source: .ttlGuess))
            }
            if let r = await ssdp {
                enrichments.append(DeviceEnrichment(mac: nil, manufacturer: r.manufacturer, inferredOS: nil,
                                                     openPorts: [], source: .ssdpDescription))
            }
            let scannedPorts = await ports
            if !scannedPorts.isEmpty {
                var bannerManufacturer: String?
                var bannerOS: String?
                for p in scannedPorts {
                    guard let banner = p.banner else { continue }
                    let guess = guessFromBanner(banner)
                    bannerManufacturer = bannerManufacturer ?? guess.manufacturer
                    bannerOS = bannerOS ?? guess.os
                }
                enrichments.append(DeviceEnrichment(mac: nil, manufacturer: bannerManufacturer, inferredOS: bannerOS,
                                                     openPorts: scannedPorts.map(\.port), source: .portBanner))
            }

            results.send((ip: ip, enrichments: enrichments))
            activeTasks.removeValue(forKey: taskID)
        }
        activeTasks[taskID] = task
    }

    /// Narrower entry point dedicated to the SSDP device-description fetch.
    /// `enrich()` fires exactly once per IP (Ruling 14), using whichever
    /// `Device` was first-seen for it — but the local port-80 subnet sweep
    /// often discovers an IP (with no `locationURL` yet) around the same
    /// time the SSDP reply for that same IP arrives, so `enrich()`'s
    /// one-shot call frequently fires with `locationURL: nil` and the SSDP
    /// description never gets fetched even though a later `Device` update
    /// for the same IP does carry a valid `locationURL`. `NetworkScanViewModel`
    /// calls this independently, once per IP, the first time any row for
    /// that IP reveals a non-nil `locationURL` — regardless of whether
    /// `enrich()` already fired for that IP via an earlier row.
    func enrichDescription(ip: String, locationURL: URL) {
        guard SSDPDescriptionFetcher.isLANLocalAddress(ip) else {
            logger.debug("enrichDescription: refusing non-LAN-local ip \(ip, privacy: .public)")
            return
        }
        let taskID = UUID()
        let task = Task {
            defer { activeTasks.removeValue(forKey: taskID) }
            guard let info = await limitedSSDPFetch(locationURL: locationURL) else { return }
            let enrichment = DeviceEnrichment(mac: nil, manufacturer: info.manufacturer, inferredOS: nil,
                                               openPorts: [], source: .ssdpDescription)
            results.send((ip: ip, enrichments: [enrichment]))
        }
        activeTasks[taskID] = task
    }

    /// Cancels every in-flight `enrich`/`enrichDescription` task and clears
    /// the tracking set. Call whenever a fresh scan starts so a previous
    /// scan's still-running probes never bleed results into (or race) the
    /// new scan.
    func cancelAll() {
        for task in activeTasks.values { task.cancel() }
        activeTasks.removeAll()
    }

    private func limitedUbiquitiProbe(ip: String) async -> UbiquitiDiscoveryReply? {
        await limiter.acquire()
        defer { Task { await limiter.release() } }
        return await ubiquitiProbe.probe(ip: ip, pacer: udpPacer, timeout: probeTimeout)
    }

    private func limitedASUSProbe(ip: String) async -> ASUSDiscoveryReply? {
        await limiter.acquire()
        defer { Task { await limiter.release() } }
        return await asusProbe.probe(ip: ip, pacer: udpPacer, timeout: probeTimeout)
    }

    private func limitedJNAPHNAPProbe(ip: String) async -> JNAPHNAPInfo? {
        await limiter.acquire()
        defer { Task { await limiter.release() } }
        return await jnapHnapProbe.probe(ip: ip, timeout: jnapHnapAttemptTimeout)
    }

    private func limitedNetBIOSProbe(ip: String) async -> NetBIOSReply? {
        await limiter.acquire()
        defer { Task { await limiter.release() } }
        return await netBIOSProbe.probe(ip: ip, pacer: udpPacer, timeout: probeTimeout)
    }

    private func limitedTTLProbe(ip: String) async -> String? {
        await limiter.acquire()
        defer { Task { await limiter.release() } }
        // TTLProbe now sends a real NBSTAT-to-port-137 query (Task 8 was redesigned -
        // the original ICMP-unreachable mechanism cannot work on Darwin) and so takes
        // a pacer like the other two UDP probes.
        return await ttlProbe.probe(ip: ip, pacer: udpPacer, timeout: probeTimeout)
    }

    private func limitedSSDPFetch(locationURL: URL?) async -> SSDPDescriptionInfo? {
        // Guarded here (rather than at the `async let` call site with an
        // Optional.map closure) because `async let`'s initializer must be a
        // direct async call expression — wrapping it in a synchronous
        // closure ("locationURL.map { limitedSSDPFetch(...) }") does not
        // type-check ("async call in a function that does not support
        // concurrency"), since Optional.map's closure parameter isn't async.
        guard let locationURL else { return nil }
        await limiter.acquire()
        defer { Task { await limiter.release() } }
        return await ssdpFetcher.fetch(locationURL: locationURL, timeout: fetchTimeout)
    }

    private func limitedPortScan(ip: String) async -> [ScannedPort] {
        await limiter.acquire()
        defer { Task { await limiter.release() } }
        return await withCheckedContinuation { continuation in
            PortScanner().scan(ip: ip, ports: PortScanner.uniFiRelevantPorts, timeout: portScanTimeout) { scanned in
                continuation.resume(returning: scanned)
            }
        }
    }
}
