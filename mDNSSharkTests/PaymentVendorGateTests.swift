// mDNSSharkTests/PaymentVendorGateTests.swift
import Testing
import Foundation
import DeviceFingerprint
@testable import mDNSShark

@MainActor
@Suite("Payment-vendor gate: ARP is read first, and a payment vendor's MAC gets no active sends")
struct PaymentVendorGateTests {
    /// Every send the view model makes, in order, plus each ARP read, so a test can check what happened before what.
    private final class Recorder {
        var events: [String] = []
        var probes: [String] = []
        var fetches: [String] = []
        var wifi: [String] = []
        var triggers: [String] = []
        var lookups: [String] = []
    }

    private final class Counter { var value = 0 }

    private let phone = "10.10.30.5"
    private let paxMAC = "00:17:6f:01:02:03"
    private let appleMAC = "f0:d1:a9:01:02:03"
    private let econoliteMAC = "00:04:81:01:02:03"
    private let econolite = "Econolite Control Products, Inc."
    private let pax = "PAX Computer Technology(Shenzhen) Ltd."
    private let fast = PaymentVendorGate.Timing(pollInterval: .milliseconds(10), maxWait: .milliseconds(30))

    private func viewModel(_ rec: Recorder, arp: @escaping (String) -> ARPLookup) -> NetworkScanViewModel {
        let subnet = LocalInterfaces.IPv4Subnet(network: LocalInterfaces.ipv4Value("10.10.30.0")!, prefixLength: 24)
        let own = LocalInterfaces.OwnAddresses(primary: [phone], all: [phone], ipv4Subnets: [subnet])
        return NetworkScanViewModel(
            ownAddresses: { own },
            probe: { ip, _ in rec.probes.append(ip); rec.events.append("probe") },
            descriptionFetch: { ip, _ in rec.fetches.append(ip); rec.events.append("fetch") },
            googleWifi: { ip in rec.wifi.append(ip); rec.events.append("wifi") },
            arpLookup: { ip in rec.lookups.append(ip); rec.events.append("arp"); return arp(ip) },
            arpTrigger: { ip in rec.triggers.append(ip); rec.events.append("trigger"); return nil },
            vendorGateTiming: fast)
    }

    /// A Cast row with a LOCATION, so the description fetch and the Google Wifi probe would both fire for an ungated host.
    private func castRow(ip: String, host: String) -> [NetworkScanner.Device] {
        func row(_ name: String, location: URL?) -> NetworkScanner.Device {
            let row = NetworkScanner.Device(serviceName: name, serviceDomain: "local.", serviceType: "_googlecast._tcp")
            row.resolvedIPAddress = ip
            row.hostName = host
            row.port = 8009
            row.resolveSettled = true
            row.locationURL = location
            return row
        }
        return [row("Cast", location: nil), row("Cast2", location: URL(string: "http://\(ip):49152/desc.xml"))]
    }

    private func waitUntil(_ condition: () -> Bool) async {
        for _ in 0..<200 where !condition() { try? await Task.sleep(for: .milliseconds(10)) }
    }

    @Test("a payment-vendor MAC yields only ARP and OUI facts, zero sends, and a settled row with the label")
    func paymentVendorGetsOnlyPassiveFacts() {
        let rec = Recorder()
        let vm = viewModel(rec) { $0 == "10.10.30.40" ? .resolved(paxMAC) : .missing }

        let devices = vm.merge(raw: castRow(ip: "10.10.30.40", host: "pos.local."))

        #expect(rec.probes.isEmpty && rec.fetches.isEmpty && rec.wifi.isEmpty && rec.triggers.isEmpty)
        #expect(devices.count == 1)
        #expect(devices.first?.probesSettled == true)
        #expect(devices.first?.macAddress == paxMAC)
        #expect(devices.first?.manufacturer == pax)
        #expect(devices.first?.paymentVendorSkip == PaymentVendorSkip(vendor: pax, inferred: false, sentARPTrigger: false))
        let sources = Set((vm.rawEnrichmentsByIP["10.10.30.40"] ?? []).map(\.source))
        #expect(!sources.isEmpty && sources.isSubset(of: [.arpTableLookup, .ouiLookup]))

        _ = vm.merge(raw: castRow(ip: "10.10.30.40", host: "pos.local."))
        #expect(rec.probes.isEmpty && rec.fetches.isEmpty && rec.wifi.isEmpty)
    }

    @Test("an unknown vendor fans out as before, with the ARP read first")
    func unknownVendorFansOut() {
        let rec = Recorder()
        let vm = viewModel(rec) { _ in .resolved(appleMAC) }

        let devices = vm.merge(raw: castRow(ip: "10.10.30.41", host: "tv.local."))

        #expect(rec.probes == ["10.10.30.41"])
        #expect(rec.fetches == ["10.10.30.41"])
        #expect(rec.wifi == ["10.10.30.41"])
        #expect(rec.events.first == "arp")
        #expect(devices.first?.paymentVendorSkip == nil)
        #expect(devices.first?.probesSettled == false)
    }

    @Test("a host with no ARP entry waits, sends the one trigger, then fans out, and nothing is sent before the last ARP read")
    func missingEntryWaitsThenFansOut() async {
        let rec = Recorder()
        let vm = viewModel(rec) { _ in .missing }

        let first = vm.merge(raw: castRow(ip: "10.10.30.42", host: "box.local."))
        #expect(rec.probes.isEmpty && rec.fetches.isEmpty && rec.wifi.isEmpty)
        #expect(first.first?.probesSettled == false)

        await waitUntil { !rec.probes.isEmpty }

        #expect(rec.probes == ["10.10.30.42"])
        #expect(rec.fetches == ["10.10.30.42"])
        #expect(rec.wifi == ["10.10.30.42"])
        #expect(rec.triggers == (PaymentVendorGate.sendsNBSTATTriggerAfterWait ? ["10.10.30.42"] : []))
        #expect(rec.lookups.count >= 3)
        let lastARP = rec.events.lastIndex(of: "arp") ?? .max
        let firstSend = rec.events.firstIndex { $0 == "probe" || $0 == "fetch" || $0 == "wifi" } ?? -1
        #expect(lastARP < firstSend)
        let later = vm.merge(raw: castRow(ip: "10.10.30.42", host: "box.local."))
        #expect(later.first?.paymentVendorSkip == nil)
        #expect(first.first?.paymentVendorSkip == nil)
        #expect(!(vm.rawEnrichmentsByIP["10.10.30.42"] ?? []).contains { $0.source == .arpTableLookup })
    }

    @Test("an entry that appears during the wait still gates a payment vendor, with no trigger and no sends")
    func entryAppearingDuringWaitGates() async {
        let rec = Recorder()
        let reads = Counter()
        let vm = viewModel(rec) { _ in
            reads.value += 1
            return reads.value < 3 ? .missing : .resolved(paxMAC)
        }
        let rows = castRow(ip: "10.10.30.43", host: "pos2.local.")

        _ = vm.merge(raw: rows)
        await waitUntil { vm.rawEnrichmentsByIP["10.10.30.43"] != nil }
        let devices = vm.merge(raw: rows)

        #expect(rec.probes.isEmpty && rec.fetches.isEmpty && rec.wifi.isEmpty && rec.triggers.isEmpty)
        #expect(devices.first?.probesSettled == true)
        #expect(devices.first?.paymentVendorSkip?.vendor == pax)
    }

    @Test("an off-subnet host is gated by A0 first: no ARP read, no sends, settled, no payment label")
    func offSubnetGatedBeforeARP() {
        let rec = Recorder()
        let vm = viewModel(rec) { _ in .resolved(paxMAC) }

        let devices = vm.merge(raw: castRow(ip: "10.10.10.87", host: "cam.local."))

        #expect(rec.lookups.isEmpty)
        #expect(rec.probes.isEmpty && rec.fetches.isEmpty && rec.wifi.isEmpty)
        #expect(devices.first?.probesSettled == true)
        #expect(devices.first?.isOnLocalSubnet == false)
        #expect(devices.first?.paymentVendorSkip == nil)
    }

    @Test("a rescan during the ARP wait cancels it: no sends from the old scan, and the next merge reads ARP again")
    func rescanDuringWaitCancelsGate() async {
        let rec = Recorder()
        let reads = Counter()
        let slow = PaymentVendorGate.Timing(pollInterval: .milliseconds(100), maxWait: .milliseconds(300))
        let subnet = LocalInterfaces.IPv4Subnet(network: LocalInterfaces.ipv4Value("10.10.30.0")!, prefixLength: 24)
        let own = LocalInterfaces.OwnAddresses(primary: [phone], all: [phone], ipv4Subnets: [subnet])
        let vm = NetworkScanViewModel(
            ownAddresses: { own },
            probe: { ip, _ in rec.probes.append(ip) },
            descriptionFetch: { ip, _ in rec.fetches.append(ip) },
            googleWifi: { ip in rec.wifi.append(ip) },
            arpLookup: { _ in reads.value += 1; return reads.value == 1 ? .missing : .resolved(appleMAC) },
            arpTrigger: { ip in rec.triggers.append(ip); return nil },
            vendorGateTiming: slow)
        let rows = castRow(ip: "10.10.30.45", host: "late.local.")

        _ = vm.merge(raw: rows)
        #expect(reads.value == 1)
        vm.resetForNewScan()
        try? await Task.sleep(for: .milliseconds(600))
        #expect(rec.probes.isEmpty && rec.fetches.isEmpty && rec.wifi.isEmpty && rec.triggers.isEmpty)

        _ = vm.merge(raw: rows)
        #expect(reads.value == 2)
        #expect(rec.probes == ["10.10.30.45"])
    }

    @Test("an IPv6-only effective address is never gated or probed: no ARP read, no probe set, and the row reads Not probed")
    func ipv6OnlyPassesUngated() {
        let rec = Recorder()
        let vm = viewModel(rec) { _ in .resolved(paxMAC) }

        let devices = vm.merge(raw: castRow(ip: "fd00::40", host: "v6.local."))

        #expect(rec.lookups.isEmpty)
        #expect(rec.probes.isEmpty)
        #expect(devices.first?.paymentVendorSkip == nil)
        #expect(devices.first?.wasProbed == false)
    }

    @Test("an inferred vendor is badged with a question mark, a direct one is not")
    func inferredBadgeHasQuestionMark() {
        #expect(PaymentVendorSkip(vendor: pax, inferred: false, sentARPTrigger: false).badgeText == "Payment terminal")
        #expect(PaymentVendorSkip(vendor: pax, inferred: true, sentARPTrigger: false).badgeText == "Payment terminal?")
        #expect(PaymentVendorSkip(category: .infrastructure, vendor: econolite, inferred: true, sentARPTrigger: false).badgeText == "Roadside equipment?")
    }

    @Test("a never-probed host is not secure: payment-gated and off-subnet hosts are not probed, a normal settled host is secure")
    func neverProbedIsNotSecure() {
        var gated = DiscoveredDevice(hostname: "pos", ipAddress: "10.10.30.40")
        gated.probesSettled = true
        gated.paymentVendorSkip = PaymentVendorSkip(vendor: pax, inferred: false, sentARPTrigger: false)
        var other = DiscoveredDevice(hostname: "cam", ipAddress: "10.10.10.87")
        other.probesSettled = true
        other.isOnLocalSubnet = false
        var normal = DiscoveredDevice(hostname: "tv", ipAddress: "10.10.30.41")
        normal.probesSettled = true
        normal.isOnLocalSubnet = true

        #expect(!gated.wasProbed && !other.wasProbed && normal.wasProbed)
        #expect(TopologyNode(device: gated).securityStatus == .notProbed)
        #expect(TopologyNode(device: other).securityStatus == .notProbed)
        #expect(TopologyNode(device: normal).securityStatus == .secure)
        #expect(SecurityStatus.notProbed.accessibilityName == "not probed")
        #expect(!SecurityStatus.notProbed.accessibilityName.contains("secure"))
    }

    @Test("the phone's own row is never gated or hidden, even when its MAC reads as a payment vendor")
    func ownRowNeverGated() {
        let rec = Recorder()
        let vm = viewModel(rec) { _ in .resolved(paxMAC) }
        let phoneRow = NetworkScanner.Device(serviceName: "Phone", serviceDomain: "local.", serviceType: "_rdlink._tcp")
        phoneRow.resolvedIPAddress = phone
        phoneRow.hostName = "phone.local."
        phoneRow.port = 49152
        phoneRow.resolveSettled = true

        let devices = vm.merge(raw: [phoneRow] + castRow(ip: "10.10.30.44", host: "pos3.local."))

        let own = devices.first { $0.ipAddress == phone }
        #expect(own != nil)
        #expect(own?.paymentVendorSkip == nil)
        #expect(rec.probes == [phone])
        #expect(devices.first { $0.ipAddress == "10.10.30.44" }?.paymentVendorSkip != nil)
    }

    @Test("a private MAC whose cleared form is a payment vendor is gated as inferred; near-miss vendors are not")
    func inferredAndNearMissVendors() {
        let table = ["00:17:6f:01:02:03": pax, "00:00:00:00:00:01": "Square D Company", "00:00:00:00:00:02": "Pax AB"]
        let lookup: (String) -> String? = { table[$0] }

        #expect(PaymentVendorGate.vendorSkip(forMAC: "02:17:6f:01:02:03", sentTrigger: false, vendorLookup: lookup)
                == PaymentVendorSkip(vendor: pax, inferred: true, sentARPTrigger: false))
        #expect(PaymentVendorGate.vendorSkip(forMAC: "00:00:00:00:00:01", sentTrigger: false, vendorLookup: lookup) == nil)
        #expect(PaymentVendorGate.vendorSkip(forMAC: "00:00:00:00:00:02", sentTrigger: false, vendorLookup: lookup) == nil)
        #expect(PaymentVendorGate.vendorSkip(forMAC: appleMAC, sentTrigger: false, vendorLookup: OUIDatabase.shared.manufacturer(for:)) == nil)
    }

    @Test("an infrastructure-vendor MAC gets only ARP and OUI facts, zero sends, settled, with the roadside label and note")
    func infrastructureVendorGetsOnlyPassiveFacts() {
        let rec = Recorder()
        let vm = viewModel(rec) { $0 == "10.10.30.50" ? .resolved(econoliteMAC) : .missing }

        let devices = vm.merge(raw: castRow(ip: "10.10.30.50", host: "cab.local."))

        #expect(rec.probes.isEmpty && rec.fetches.isEmpty && rec.wifi.isEmpty && rec.triggers.isEmpty)
        #expect(devices.first?.probesSettled == true)
        #expect(devices.first?.manufacturer == econolite)
        #expect(devices.first?.paymentVendorSkip == PaymentVendorSkip(category: .infrastructure, vendor: econolite, inferred: false, sentARPTrigger: false))
        #expect(devices.first?.paymentVendorSkip?.badgeText == "Roadside equipment")
        #expect(devices.first?.noOpenPortsText == "Not probed")
        let sources = Set((vm.rawEnrichmentsByIP["10.10.30.50"] ?? []).map(\.source))
        #expect(!sources.isEmpty && sources.isSubset(of: [.arpTableLookup, .ouiLookup]))

        _ = vm.merge(raw: castRow(ip: "10.10.30.50", host: "cab.local."))
        #expect(rec.probes.isEmpty && rec.fetches.isEmpty && rec.wifi.isEmpty)
    }

    @Test("the phone's own row is never gated even when its MAC reads as an infrastructure vendor")
    func ownRowNeverGatedForInfrastructure() {
        let rec = Recorder()
        let vm = viewModel(rec) { _ in .resolved(econoliteMAC) }
        let phoneRow = NetworkScanner.Device(serviceName: "Phone", serviceDomain: "local.", serviceType: "_rdlink._tcp")
        phoneRow.resolvedIPAddress = phone
        phoneRow.hostName = "phone.local."
        phoneRow.port = 49152
        phoneRow.resolveSettled = true

        let devices = vm.merge(raw: [phoneRow])

        #expect(devices.first { $0.ipAddress == phone }?.paymentVendorSkip == nil)
        #expect(rec.probes == [phone])
    }

    @Test("a private MAC whose cleared form is an infrastructure vendor is gated as inferred; excluded vendors are not")
    func infrastructureInferredAndExcluded() {
        let table = ["00:04:81:01:02:03": econolite, "00:00:00:00:00:01": "FLIR Systems", "00:00:00:00:00:02": "Kapsch Ag"]
        let lookup: (String) -> String? = { table[$0] }

        #expect(PaymentVendorGate.vendorSkip(forMAC: "02:04:81:01:02:03", sentTrigger: true, vendorLookup: lookup)
                == PaymentVendorSkip(category: .infrastructure, vendor: econolite, inferred: true, sentARPTrigger: true))
        #expect(PaymentVendorGate.vendorSkip(forMAC: "00:00:00:00:00:01", sentTrigger: false, vendorLookup: lookup) == nil)
        #expect(PaymentVendorGate.vendorSkip(forMAC: "00:00:00:00:00:02", sentTrigger: false, vendorLookup: lookup) == nil)
    }

    @Test("infrastructure label and note text, with the conditional clauses")
    func infrastructureLabelAndNote() {
        let plain = PaymentVendorSkip(category: .infrastructure, vendor: econolite, inferred: false, sentARPTrigger: false).note
        #expect(plain == "Vendor makes traffic-control, roadside or licence plate equipment, so mDNSShark skipped its device probes for this address. The subnet sweep's single connection attempt to port 80 runs before any vendor is known, so it is not skipped.")
        let both = PaymentVendorSkip(category: .infrastructure, vendor: econolite, inferred: true, sentARPTrigger: true).note
        #expect(both.contains("One NetBIOS name query was sent before the vendor was known"))
        #expect(both.contains("inferred"))
        #expect(PaymentVendorSkip.detail == "identified from MAC vendor only, not probed")
    }

    @Test("label and note text are present for a payment device and absent for others")
    func labelAndNoteText() {
        #expect(PaymentVendorSkip.label == "Payment terminal")
        #expect(PaymentVendorSkip.detail == "identified from MAC vendor only, not probed")
        var device = DiscoveredDevice(hostname: "pos", ipAddress: "10.10.30.40")
        #expect(device.paymentVendorSkip == nil)
        #expect(device.noOpenPortsText == "None")

        device.paymentVendorSkip = PaymentVendorSkip(vendor: pax, inferred: false, sentARPTrigger: false)
        let note = device.paymentVendorSkip?.note ?? ""
        #expect(note.hasPrefix("\(pax) makes payment or point-of-sale equipment, so mDNSShark skipped its device probes for this address."))
        #expect(note.contains(pax))
        #expect(note.contains("port 80 runs before any vendor is known"))
        #expect(!note.contains("NetBIOS") && !note.contains("inferred"))
        #expect(device.noOpenPortsText == "Not probed")

        let both = PaymentVendorSkip(vendor: pax, inferred: true, sentARPTrigger: true).note
        #expect(both.contains("One NetBIOS name query was sent before the vendor was known"))
        #expect(both.contains("inferred"))
    }
}
