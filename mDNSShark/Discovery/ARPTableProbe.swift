import Foundation
import DeviceFingerprint
import os

/// Thin app-layer wrapper around `DeviceFingerprint.ARPTableReader`, kept
/// as its own file to match every other Discovery/*Probe.swift — even
/// though, unlike the network probes it sits alongside, there's no socket
/// I/O here. Reading the kernel's ARP table is a local `sysctl(2)` call
/// against the device's own routing table, not LAN traffic, so it doesn't
/// go through `ProbeConcurrencyLimiter` or `UDPSendPacer`.
///
/// Still synchronous and blocking (a full `sysctl` + byte-parse of the
/// whole ARP table, no internal `await`), so `DeviceEnrichmentCoordinator`
/// must call it from a detached task, never inline on its `@MainActor`
/// enrichment `Task` — inline, it serializes every device's enrichment
/// behind this one's sysctl call, starving the main actor of the slots
/// the other probes' continuations (port scan included) need to resume
/// on, and can blow their timeouts across an entire scan.
final class ARPTableProbe {
    private let logger = Logger(subsystem: "com.mDNSShark", category: "ARPTableProbe")

    /// Real link-layer MAC for `ip` if the kernel's ARP table has a
    /// resolved (non-zero) entry for it. Nil on iOS 18-26 (the sandbox
    /// zeroes the bytes), before the `topology-observation` entitlement is
    /// granted, or if this device has never ARPed for `ip` at all — see
    /// todo.md item 4.
    func macAddress(forIP ip: String) -> String? {
        let mac = ARPTableReader.macAddress(forIP: ip)
        if mac == nil {
            logger.debug("ARPTableProbe: no resolved ARP entry for \(ip, privacy: .public)")
        }
        return mac
    }
}
