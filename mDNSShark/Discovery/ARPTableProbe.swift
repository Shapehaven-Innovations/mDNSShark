import Foundation
import DeviceFingerprint

/// Thin app-layer wrapper around `DeviceFingerprint.ARPTableReader`, kept
/// as its own file to match every other Discovery/*Probe.swift, even
/// though, unlike the network probes it sits alongside, there's no socket
/// I/O here. Reading the kernel's ARP table is a local `sysctl(2)` call
/// against the device's own routing table, not LAN traffic, so it doesn't
/// go through `ProbeConcurrencyLimiter` or `UDPSendPacer`.
///
/// Still synchronous and blocking (a full `sysctl` + byte-parse of the
/// whole ARP table, no internal `await`): the vendor gate's first look runs
/// on the main actor once per merge pass thanks to the shared snapshot, and
/// its polls run on a detached task. A nil MAC is expected on iOS 18-26
/// (the sandbox zeroes the bytes) or without the `topology-observation`
/// entitlement; see todo.md item 4.
// Sendable by hand: the cached snapshot is only touched under `lock`.
final class ARPTableProbe: @unchecked Sendable {
    // One table read shared by lookups within `snapshotLifetime`, so a merge pass over many new hosts reads the table once.
    private let lock = NSLock()
    private var snapshot: (entries: [ARPTableEntry], readAt: ContinuousClock.Instant)?
    private static let snapshotLifetime: Duration = .milliseconds(100)

    /// What the ARP table says about `ip` right now, for the payment-vendor gate; safe to call from any thread.
    func lookup(ip: String) -> ARPLookup {
        lock.lock()
        let cached = snapshot.flatMap { ContinuousClock.now - $0.readAt < Self.snapshotLifetime ? $0.entries : nil }
        lock.unlock()
        if let cached { return ARPLookup.state(forIP: ip, in: cached) }
        let entries = ARPTableReader.readEntries()
        lock.lock()
        snapshot = (entries, ContinuousClock.now)
        lock.unlock()
        return ARPLookup.state(forIP: ip, in: entries)
    }
}
