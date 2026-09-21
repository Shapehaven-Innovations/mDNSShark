import Foundation
import DeviceFingerprint
import os

/// Thin app-layer wrapper around `DeviceFingerprint.ARPTableReader`, kept
/// as its own file to match every other Discovery/*Probe.swift — even
/// though, unlike the network probes it sits alongside, there's no socket
/// I/O here. Reading the kernel's ARP table is a local `sysctl(2)` call
/// against the device's own routing table, not LAN traffic, so it doesn't
/// go through `ProbeConcurrencyLimiter` or `UDPSendPacer` and is safe to
/// call synchronously from `DeviceEnrichmentCoordinator`.
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
