// mDNSSharkTests/OffNetworkProbeTests.swift
import Testing
import Foundation
import DeviceFingerprint
@testable import mDNSShark

@MainActor
@Suite("Probe this device: a one-scan request probes one off-network address with no ARP and no vendor gate")
struct OffNetworkProbeTests {
    private final class Rec {
        var probes: [String] = []
        var fetches: [String] = []
        var wifi: [String] = []
        var lookups: [String] = []
        var triggers: [String] = []
    }

    private let phone = "10.10.30.5"
    private let paxMAC = "00:17:6f:01:02:03"

    private func viewModel(_ rec: Rec) -> NetworkScanViewModel {
        let subnet = LocalInterfaces.IPv4Subnet(network: LocalInterfaces.ipv4Value("10.10.30.0")!, prefixLength: 24)
        let own = LocalInterfaces.OwnAddresses(primary: [phone], all: [phone], ipv4Subnets: [subnet])
        return NetworkScanViewModel(ownAddresses: { own }, probe: { ip, _ in rec.probes.append(ip) },
                                    descriptionFetch: { ip, _ in rec.fetches.append(ip) }, googleWifi: { rec.wifi.append($0) },
                                    arpLookup: { rec.lookups.append($0); return .hidden }, arpTrigger: { rec.triggers.append($0); return nil })
    }

    private func row(type: String = "_http._tcp", name: String, ip: String, host: String, location: URL? = nil,
                     txt: [String: String]? = nil) -> NetworkScanner.Device {
        let row = NetworkScanner.Device(serviceName: name, serviceDomain: "local.", serviceType: type)
        row.resolvedIPAddress = ip
        row.hostName = host
        row.port = 80
        row.resolveSettled = true
        row.locationURL = location
        row.txtRecords = txt
        return row
    }

    @Test("a request on an off-subnet IP sends one probe and no ARP read, leaves the row unsettled, and reads Probed")
    func requestProbesOnce() {
        let rec = Rec()
        let vm = viewModel(rec)
        let r = row(name: "Cam", ip: "10.10.10.87", host: "cam.local.")
        vm.apply(raw: [r])
        #expect(rec.probes.isEmpty)
        #expect(vm.devices.first?.wasProbed == false)

        #expect(vm.probeAnyway(ip: "10.10.10.87"))
        vm.apply(raw: [r])

        #expect(rec.probes == ["10.10.10.87"])
        #expect(rec.lookups.isEmpty && rec.triggers.isEmpty)
        #expect(vm.devices.first?.probesSettled == false)
        #expect(vm.devices.first?.wasProbed == true)
        #expect(vm.devices.first?.probeRequested == true)
    }

    @Test("after a new scan the request is gone: nothing is probed and the row is Not probed again")
    func resetClearsRequest() {
        let rec = Rec()
        let vm = viewModel(rec)
        let r = row(name: "Cam", ip: "10.10.10.87", host: "cam.local.")
        _ = vm.merge(raw: [r])
        #expect(vm.probeAnyway(ip: "10.10.10.87"))
        _ = vm.merge(raw: [r])
        #expect(rec.probes == ["10.10.10.87"])

        vm.resetForNewScan()
        let devices = vm.merge(raw: [r])

        #expect(rec.probes == ["10.10.10.87"])
        #expect(devices.first?.wasProbed == false)
        #expect(devices.first?.probesSettled == true)
    }

    @Test("a non-private address and an IPv6-only group are refused")
    func refusals() {
        let rec = Rec()
        let vm = viewModel(rec)
        let far = row(name: "Far", ip: "8.8.8.8", host: "far.local.")
        let v6 = row(type: "_matter._tcp", name: "T", ip: "fd12::1", host: "t.local.")
        vm.apply(raw: [far, v6])

        #expect(!vm.probeAnyway(ip: "8.8.8.8"))
        #expect(!vm.probeAnyway(ip: "fd12::1"))
        vm.apply(raw: [far, v6])

        #expect(rec.probes.isEmpty)
        #expect(vm.devices.allSatisfy { !$0.wasProbed })
    }

    @Test("a request for an on-subnet IP does not probe twice")
    func onSubnetNotTwice() {
        let rec = Rec()
        let vm = viewModel(rec)
        let r = row(name: "Printer", ip: "10.10.30.40", host: "p.local.")
        vm.apply(raw: [r])
        vm.probeAnyway(ip: "10.10.30.40")
        vm.apply(raw: [r])
        #expect(rec.probes == ["10.10.30.40"])
        #expect(vm.devices.first?.probeRequested == false)
    }

    @Test("a host whose MAC vendor makes payment equipment refuses the request and stays Not probed")
    func paymentRefused() {
        let rec = Rec()
        let vm = viewModel(rec)
        let r = row(name: "POS", ip: "10.10.10.90", host: "pos.local.", txt: ["mac": paxMAC])
        vm.apply(raw: [r])

        #expect(!vm.probeAnyway(ip: "10.10.10.90"))
        vm.apply(raw: [r])

        #expect(rec.probes.isEmpty)
        #expect(vm.devices.first?.paymentVendorSkip != nil)
        #expect(vm.devices.first?.wasProbed == false)
    }

    @Test("the description fetch and Google Wifi probe follow the request")
    func fetchersFollowAllowed() {
        let rec = Rec()
        let vm = viewModel(rec)
        let url = URL(string: "http://10.10.10.87:49152/desc.xml")
        let a = row(type: "_googlecast._tcp", name: "Cast", ip: "10.10.10.87", host: "cast.local.")
        let b = row(type: "_googlecast._tcp", name: "Cast2", ip: "10.10.10.87", host: "cast.local.", location: url)
        _ = vm.merge(raw: [a, b])
        #expect(rec.fetches.isEmpty && rec.wifi.isEmpty)

        #expect(vm.probeAnyway(ip: "10.10.10.87"))
        _ = vm.merge(raw: [a, b])
        _ = vm.merge(raw: [a, b])

        #expect(rec.probes == ["10.10.10.87"])
        #expect(rec.fetches == ["10.10.10.87"])
        #expect(rec.wifi == ["10.10.10.87"])
    }

    // MARK: networkNote

    private func device(ip: String, onLocal: Bool?, types: [String] = [], ssdp: String? = nil) -> DiscoveredDevice {
        var d = DiscoveredDevice(hostname: "h", ipAddress: ip, bonjourServices: types.map { BonjourService(serviceType: $0, serviceName: "n", port: 1) })
        d.isOnLocalSubnet = onLocal
        d.ssdpServer = ssdp
        return d
    }

    @Test("networkNote: same network, probed")
    func noteSame() {
        let d = device(ip: "10.10.30.9", onLocal: true, types: ["_http._tcp"])
        #expect(d.networkNote(ownCIDRs: ["10.10.30.0/24"]) == ["Same network as this phone (10.10.30.0/24)", "Bonjour advertisement (_http._tcp)", "Probed"])
    }

    @Test("networkNote: outside via Bonjour only adds the repeater note and Not probed")
    func noteOutside() {
        let d = device(ip: "10.10.10.87", onLocal: false, types: ["_http._tcp"])
        let lines = d.networkNote(ownCIDRs: ["10.10.30.0/24"])
        #expect(lines.first == "Outside this phone's network (device 10.10.10.87, outside: 10.10.30.0/24)")
        #expect(lines.contains("Your router may be repeating this advertisement from another network (not confirmed)."))
        #expect(lines.last == "Not probed: on another network")
    }

    @Test("networkNote: SSDP reply drops the repeater note, a request reads Probes pending, then Probed on request")
    func noteSSDPAndRequest() {
        var d = device(ip: "10.10.10.87", onLocal: false, ssdp: "Linux UPnP")
        d.probeRequested = true
        let lines = d.networkNote(ownCIDRs: ["10.10.30.0/24"])
        #expect(lines.contains("SSDP reply"))
        #expect(!lines.contains { $0.hasPrefix("Your router") })
        #expect(lines.last == "Probes pending")
        d.probesSettled = true
        #expect(d.networkNote(ownCIDRs: ["10.10.30.0/24"]).last == "Probed on request")
    }

    @Test("networkNote: unknown network, payment skip and refused probe lines")
    func noteOthers() {
        #expect(device(ip: "fd12::1", onLocal: nil).networkNote(ownCIDRs: []).first == "Network not known")
        var pay = device(ip: "10.10.10.9", onLocal: false)
        pay.paymentVendorSkip = PaymentVendorSkip(vendor: "PAX", inferred: false, sentARPTrigger: false)
        pay.probeRequested = true
        #expect(pay.wasProbed == false)
        #expect(pay.networkNote(ownCIDRs: ["10.10.30.0/24"]).last == "Not probed: payment or roadside vendor")
        var v6 = device(ip: "fd12::1", onLocal: nil)
        v6.probeRefused = true
        #expect(v6.networkNote(ownCIDRs: []).last == "Not probed: IPv6 only or non-local address")
    }

    // MARK: layout and label

    @Test("layout: the gateway is the hub, off-network nodes come last, and the hub is never off-network when an on-subnet device exists")
    func layoutRules() {
        var off1 = device(ip: "10.10.10.1", onLocal: false)
        off1.isDefaultGateway = false
        let off2 = device(ip: "10.10.10.2", onLocal: false)
        let on1 = device(ip: "10.10.30.9", onLocal: true)
        var gw = device(ip: "10.10.30.1", onLocal: true)
        gw.isDefaultGateway = true
        let on2 = device(ip: "10.10.30.8", onLocal: nil)

        let withGateway = TopologyView.layout([off1, off2, on1, gw, on2])
        #expect(withGateway.hub?.id == gw.id)
        #expect(withGateway.others.map(\.id) == [on1.id, on2.id, off1.id, off2.id])

        let noGateway = TopologyView.layout([off1.withoutGateway(), off2, on1])
        #expect(noGateway.hub?.id == on1.id)
        #expect(noGateway.others.map(\.id) == [off1.id, off2.id])

        let allOff = TopologyView.layout([off2, off1.withoutGateway()])
        #expect(allOff.hub?.id == off2.id)
        #expect(TopologyView.layout([]).hub == nil)
    }

    @Test("layout: with the gateway answer unknown, an off-network .1 is not the hub while an on-subnet device exists")
    func layoutUnknownGateway() {
        let off = device(ip: "10.10.10.1", onLocal: false)
        let on = device(ip: "10.10.30.9", onLocal: true)
        #expect(off.isGateway)
        let result = TopologyView.layout([off, on])
        #expect(result.hub?.id == on.id)
        #expect(result.others.map(\.id) == [off.id])
    }

    @Test("the confirmation dialog text is the specified wording with the literal address and CIDRs")
    func dialogWording() {
        #expect(DeviceDetailView.probeConfirmation(ip: "10.10.10.87", phoneCIDRs: ["10.10.30.0/24"])
                == "10.10.10.87 is outside 10.10.30.0/24. mDNSShark will send its standard probes (about 50 packets) to this one address through your router. The payment-terminal check cannot run across a router. Only probe networks you are allowed to test.")
    }

    @Test("a request for one address of a two-address group probes only that address, even after the effective address changes")
    func requestOneOfTwoAddresses() {
        let rec = Rec()
        let vm = viewModel(rec)
        let a = row(name: "UDM", ip: "10.10.50.1", host: "udm.local.")
        vm.apply(raw: [a])
        #expect(vm.probeAnyway(ip: "10.10.50.1"))
        vm.apply(raw: [a])
        #expect(rec.probes == ["10.10.50.1"])

        let b = row(type: "_ssh._tcp", name: "UDM", ip: "10.10.10.1", host: "udm.local.")
        vm.apply(raw: [a, b])
        vm.apply(raw: [a, b])
        #expect(rec.probes == ["10.10.50.1"])
    }

    @Test("a request during the scan-start hold does not re-merge last scan's rows")
    func requestDuringHold() {
        let rec = Rec()
        let vm = viewModel(rec)
        let r = row(name: "Cam", ip: "10.10.10.87", host: "cam.local.")
        let near = row(name: "Printer", ip: "10.10.30.40", host: "p.local.")
        vm.apply(raw: [r, near])
        #expect(rec.probes == ["10.10.30.40"])

        vm.resetForNewScan()
        #expect(vm.probeAnyway(ip: "10.10.10.87"))
        #expect(rec.probes == ["10.10.30.40"])

        vm.apply(raw: [r, near])
        #expect(Set(rec.probes) == ["10.10.30.40", "10.10.10.87"])
    }

    @Test("link-local and loopback addresses are refused")
    func linkLocalRefused() {
        let vm = viewModel(Rec())
        #expect(!vm.probeAnyway(ip: "169.254.1.5"))
        #expect(!vm.probeAnyway(ip: "127.0.0.1"))
    }

    @Test("VoiceOver label names an off-network node")
    func voiceOver() {
        let off = TopologyNode(device: device(ip: "10.10.10.87", onLocal: false))
        let on = TopologyNode(device: device(ip: "10.10.30.9", onLocal: true))
        #expect(off.accessibilityLabel.hasSuffix(", on another network"))
        #expect(!on.accessibilityLabel.contains("another network"))
    }
}

private extension DiscoveredDevice {
    /// A copy with the gateway answer known and false, so the ".1" address guess cannot make it a hub.
    func withoutGateway() -> DiscoveredDevice {
        var copy = self
        copy.isDefaultGateway = false
        return copy
    }
}
