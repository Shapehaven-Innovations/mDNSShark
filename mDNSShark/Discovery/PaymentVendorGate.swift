// mDNSShark/Discovery/PaymentVendorGate.swift
import Foundation
import DeviceFingerprint

/// Reads a host's MAC from the ARP table before anything active is sent to it, and says whether its vendor makes payment or roadside equipment.
/// Platform-neutral: the table read, the trigger and the timing are passed in.
/// Constraint: a gated host must never receive SNMP, vendor UDP management protocols, "Probe anyway", or any HTTP request from later stages.
enum PaymentVendorGate {
    /// How long to wait for an ARP entry that is missing at first look. Worst case per host is `maxWait` plus the trigger's own timeout.
    struct Timing {
        var pollInterval: Duration
        var maxWait: Duration
        /// Design decision 12: poll every 250 ms for up to 1.5 s, since the subnet sweep's SYN to port 80 creates the entry by then.
        static let standard = Timing(pollInterval: .milliseconds(250), maxWait: .milliseconds(1500))
    }

    /// Device test T9: one NBSTAT datagram for a host still missing from the ARP table after the wait, so the kernel resolves it.
    /// Set to false if T9 shows entries always exist within `Timing.standard.maxWait`.
    static let sendsNBSTATTriggerAfterWait = true

    /// The MAC the gate decides on and where it came from.
    struct Reading: Equatable {
        var mac: String?
        /// `.arpTableLookup` for the kernel table, `.ouiLookup` for a MAC carried in the trigger's NBSTAT reply.
        var source: EnrichmentSource
        var sentTrigger: Bool
    }

    /// Polls a missing entry until it resolves, the table turns out to hide MACs, or the wait runs out; then sends the trigger once,
    /// if given, and reads once more. `lookup` runs off the main actor because it is a blocking sysctl.
    static func waitForMAC(ip: String, lookup: @escaping @Sendable (String) -> ARPLookup, trigger: ((String) async -> String?)?,
                           timing: Timing) async -> Reading {
        let none = Reading(mac: nil, source: .arpTableLookup, sentTrigger: false)
        var waited: Duration = .zero
        while waited < timing.maxWait {
            try? await Task.sleep(for: timing.pollInterval)
            guard !Task.isCancelled else { return none }
            waited += timing.pollInterval
            switch await Task.detached(operation: { lookup(ip) }).value {
            case .resolved(let mac): return Reading(mac: mac, source: .arpTableLookup, sentTrigger: false)
            case .hidden:            return none
            case .missing:           continue
            }
        }
        guard let trigger, !Task.isCancelled else { return none }
        let replyMAC = await trigger(ip)
        if case .resolved(let mac) = await Task.detached(operation: { lookup(ip) }).value {
            return Reading(mac: mac, source: .arpTableLookup, sentTrigger: true)
        }
        return Reading(mac: replyMAC, source: .ouiLookup, sentTrigger: true)
    }

    /// The skip record when `mac` belongs to a payment or infrastructure vendor, by its own OUI or, inferred, with the locally administered bit cleared.
    static func vendorSkip(forMAC mac: String, sentTrigger: Bool, vendorLookup: (String) -> String?) -> PaymentVendorSkip? {
        func skip(_ vendor: String?, inferred: Bool) -> PaymentVendorSkip? {
            guard let vendor else { return nil }
            if PaymentVendorHint.isPaymentVendor(vendor) {
                return PaymentVendorSkip(category: .payment, vendor: vendor, inferred: inferred, sentARPTrigger: sentTrigger)
            }
            if InfrastructureVendorHint.isInfrastructureVendor(vendor) {
                return PaymentVendorSkip(category: .infrastructure, vendor: vendor, inferred: inferred, sentARPTrigger: sentTrigger)
            }
            return nil
        }
        if let found = skip(vendorLookup(mac), inferred: false) { return found }
        guard let cleared = MACAddressFacts.clearingLocalBit(mac) else { return nil }
        return skip(vendorLookup(cleared), inferred: true)
    }
}
