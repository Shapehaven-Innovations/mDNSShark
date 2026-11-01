// mDNSSharkTests/MDNSListenerTests.swift
import Testing
import Foundation
@testable import mDNSShark

@Suite("BSDMDNSListener turns recvmsg results into datagrams and reports both families in meta")
struct MDNSListenerTests {

    private let group6: [UInt8] = [0xff, 0x02] + [UInt8](repeating: 0, count: 13) + [0xfb]
    private let received = Date(timeIntervalSince1970: 1_700_000_000)
    private let linkLocal: [UInt8] = [0xfe, 0x80] + [UInt8](repeating: 0, count: 6) + [1, 2, 3, 4, 5, 6, 7, 8]
    private let up = IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST

    /// Single-interface meta, the shape every pre-multi-interface test used.
    private func meta(status: MDNSListenerStatus, ipv6Status: MDNSListenerStatus, stats: MDNSListenerStats = MDNSListenerStats()) -> [String: Any] {
        MDNSListenerMeta.dictionary(interfaces: [MDNSInterfaceReport(name: "en0", index: 13, functionalType: InterfaceFunctionalType.wifiInfra,
                                                                     status: status, ipv6Status: ipv6Status)], stats: stats)
    }

    private func descriptor(_ name: String, index: UInt32, flags: Int32? = nil, type: UInt32?, addresses: [[UInt8]],
                            netmasks: [[UInt8]: [UInt8]] = [:]) -> InterfaceDescriptor {
        InterfaceDescriptor(name: name, index: index, flags: flags ?? up, functionalType: type, addresses: addresses, ipv4Netmasks: netmasks)
    }

    private let slash24: [UInt8] = [255, 255, 255, 0]

    /// The interface list of an iPhone with Personal Hotspot on, as getifaddrs and SIOCGIFFUNCTIONALTYPE describe it.
    private var hotspotPhone: [InterfaceDescriptor] {
        [descriptor("lo0", index: 1, flags: IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_MULTICAST, type: InterfaceFunctionalType.loopback, addresses: [[127, 0, 0, 1]], netmasks: [[127, 0, 0, 1]: [255, 0, 0, 0]]),
         descriptor("pdp_ip0", index: 5, flags: IFF_UP | IFF_POINTOPOINT | IFF_RUNNING | IFF_MULTICAST, type: InterfaceFunctionalType.cellular, addresses: [[10, 20, 30, 40]], netmasks: [[10, 20, 30, 40]: [255, 255, 255, 255]]),
         descriptor("en0", index: 13, type: InterfaceFunctionalType.wifiInfra, addresses: [[192, 168, 8, 123], linkLocal], netmasks: [[192, 168, 8, 123]: slash24]),
         descriptor("awdl0", index: 15, type: InterfaceFunctionalType.wifiAWDL, addresses: [linkLocal]),
         descriptor("llw0", index: 16, type: InterfaceFunctionalType.wifiAWDL, addresses: [linkLocal]),
         descriptor("utun0", index: 17, flags: IFF_UP | IFF_POINTOPOINT | IFF_RUNNING | IFF_MULTICAST, type: nil, addresses: [[100, 64, 0, 1]], netmasks: [[100, 64, 0, 1]: slash24]),
         descriptor("anpi0", index: 7, type: InterfaceFunctionalType.intcoproc, addresses: [linkLocal]),
         descriptor("bridge100", index: 20, type: InterfaceFunctionalType.unknown, addresses: [[172, 20, 10, 1], linkLocal], netmasks: [[172, 20, 10, 1]: [255, 255, 255, 240]])]
    }

    /// The field capture of a cabled iPhone: Wi-Fi with IPv4, llw0 without, USB Ethernet to the Mac on 169.254, and the coprocessor link.
    private var cabledPhone: [InterfaceDescriptor] {
        [descriptor("en0", index: 13, type: InterfaceFunctionalType.wifiInfra, addresses: [[192, 168, 8, 123], linkLocal], netmasks: [[192, 168, 8, 123]: slash24]),
         descriptor("llw0", index: 16, type: InterfaceFunctionalType.wifiInfra, addresses: [linkLocal]),
         descriptor("en2", index: 22, type: InterfaceFunctionalType.wired, addresses: [[169, 254, 31, 7], linkLocal], netmasks: [[169, 254, 31, 7]: [255, 255, 0, 0]]),
         descriptor("anpi0", index: 7, type: InterfaceFunctionalType.wired, addresses: [linkLocal])]
    }

    private func report(_ name: String, index: UInt32, type: UInt32? = InterfaceFunctionalType.wired,
                        status: MDNSListenerStatus? = nil, ipv6Status: MDNSListenerStatus? = nil) -> MDNSInterfaceReport {
        MDNSInterfaceReport(name: name, index: index, functionalType: type,
                            status: status ?? .listening(interface: name, index: index), ipv6Status: ipv6Status ?? .listening(interface: name, index: index))
    }

    private func capture(_ name: String, index: UInt32, type: UInt32? = InterfaceFunctionalType.wired, addresses: [[UInt8]]) -> CaptureInterface {
        CaptureInterface(name: name, index: index, functionalType: type, addresses: addresses)
    }

    private func sockaddr4(_ a: [UInt8], port: UInt16) -> [UInt8] {
        var sa = sockaddr_in()
        sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_port = port.bigEndian
        sa.sin_addr = in_addr(s_addr: UInt32(a[0]) | UInt32(a[1]) << 8 | UInt32(a[2]) << 16 | UInt32(a[3]) << 24)
        return withUnsafeBytes(of: &sa) { Array($0) }
    }

    private func sockaddr6(_ a: [UInt8], port: UInt16) -> [UInt8] {
        var sa = sockaddr_in6()
        sa.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        sa.sin6_family = sa_family_t(AF_INET6)
        sa.sin6_port = port.bigEndian
        withUnsafeMutableBytes(of: &sa.sin6_addr) { $0.copyBytes(from: a) }
        return withUnsafeBytes(of: &sa) { Array($0) }
    }

    @Test func ipv4DatagramUsesSocketMetadata() {
        var cmsgs = MDNSControlMessages()
        cmsgs.ttl = 255
        cmsgs.destination = [224, 0, 0, 251]
        cmsgs.kernelTimestamp = received.addingTimeInterval(-0.05)
        let d = BSDMDNSListener.makeDatagram(sourceAddress: sockaddr4([192, 168, 8, 178], port: 5353),
                                             payload: Data([1, 2, 3]), cmsgs: cmsgs, received: received)
        #expect(d?.source == [192, 168, 8, 178])
        #expect(d?.destination == [224, 0, 0, 251])
        #expect(d?.sourcePort == 5353)
        #expect(d?.destinationPort == 5353)
        #expect(d?.ttl == 255)
        #expect(d?.timestamp == received.addingTimeInterval(-0.05))
        #expect(d?.payload == Data([1, 2, 3]))
    }

    @Test func ipv4DatagramFallsBackToGroupAndWallClock() {
        let d = BSDMDNSListener.makeDatagram(sourceAddress: sockaddr4([10, 0, 0, 9], port: 49152),
                                             payload: Data([0]), cmsgs: MDNSControlMessages(), received: received)
        #expect(d?.destination == [224, 0, 0, 251])
        #expect(d?.sourcePort == 49152)
        #expect(d?.ttl == nil)
        #expect(d?.timestamp == received)
    }

    @Test func ipv6DatagramUsesHopLimitAndPacketInfo() {
        let source: [UInt8] = [0xfe, 0x80] + [UInt8](repeating: 0, count: 6) + [0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d]
        var cmsgs = MDNSControlMessages()
        cmsgs.hopLimit = 255
        cmsgs.destination6 = group6
        let d = BSDMDNSListener.makeDatagram(sourceAddress: sockaddr6(source, port: 5353),
                                             payload: Data([9]), cmsgs: cmsgs, received: received)
        #expect(d?.source == source)
        #expect(d?.destination == group6)
        #expect(d?.ttl == 255)
        #expect(MDNSFrameBuilder.frame(d!)?.first.map { $0 >> 4 } == 6)
    }

    @Test func ipv6DatagramFallsBackToGroup() {
        let d = BSDMDNSListener.makeDatagram(sourceAddress: sockaddr6([UInt8](repeating: 1, count: 16), port: 5353),
                                             payload: Data([9]), cmsgs: MDNSControlMessages(), received: received)
        #expect(d?.destination == group6)
        #expect(d?.ttl == nil)
    }

    @Test func unknownFamilyIsRejected() {
        var bytes = sockaddr4([1, 2, 3, 4], port: 1)
        bytes[1] = UInt8(AF_UNIX)
        #expect(BSDMDNSListener.makeDatagram(sourceAddress: bytes, payload: Data(), cmsgs: MDNSControlMessages(), received: received) == nil)
        #expect(BSDMDNSListener.makeDatagram(sourceAddress: [0, 2], payload: Data(), cmsgs: MDNSControlMessages(), received: received) == nil)
    }

    @Test func metaListsOnlyTheFamiliesThatAreListening() {
        var stats = MDNSListenerStats()
        stats.frames = 20; stats.ipv4Frames = 17; stats.ipv6Frames = 3; stats.ownFrames = 15; stats.kernelStamped = 20
        let both = meta(status: .listening(interface: "en0", index: 13), ipv6Status: .listening(interface: "en0", index: 13), stats: stats)
        #expect(both["listenAddresses"] as? [String] == ["224.0.0.251:5353", "[ff02::fb]:5353"])
        #expect(both["ipv6Status"] as? String == "listening on en0 (ifindex 13)")
        #expect(both["frames"] as? Int == 20)
        #expect(both["ipv6Frames"] as? Int == 3)
        #expect(both["timestampSource"] as? String == "kernel")
        #expect(both["ttlSource"] as? String == "received")

        let v4Only = meta(status: .listening(interface: "en0", index: 13), ipv6Status: .failed(stage: "IPV6_JOIN_GROUP", errno: 49))
        #expect(v4Only["listenAddresses"] as? [String] == ["224.0.0.251:5353"])
        #expect((v4Only["ipv6Status"] as? String)?.hasPrefix("failed: IPV6_JOIN_GROUP errno 49") == true)
        #expect(v4Only["status"] as? String == "listening on en0 (ifindex 13)")
    }

    @Test func metaReportsFallbacksWithCounts() {
        var stats = MDNSListenerStats()
        stats.frames = 10; stats.kernelStamped = 8; stats.ttlMissing = 2
        let meta = meta(status: .listening(interface: "en0", index: 13), ipv6Status: .idle, stats: stats)
        #expect(meta["timestampSource"] as? String == "wallclock for 2")
        #expect(meta["ttlSource"] as? String == "fixed-255 for 2")
    }

    @Test func metaDoesNotClaimSourcesWithoutFrames() {
        let meta = meta(status: .listening(interface: "en0", index: 13), ipv6Status: .idle)
        #expect(meta["frames"] as? Int == 0)
        #expect(meta["ttlSource"] as? String == "n/a")
        #expect(meta["timestampSource"] as? String == "n/a")
    }

    @Test func unavailableStatusIsNotListening() {
        let status = MDNSListenerStatus.unavailable(reason: "no IPv4 address on en0")
        #expect(status.description == "unavailable: no IPv4 address on en0")
        #expect(status.isListening == false)
        let meta = meta(status: status, ipv6Status: .listening(interface: "en0", index: 13))
        #expect(meta["listenAddresses"] as? [String] == ["[ff02::fb]:5353"])
    }

    @Test func ownAddressesRefreshOnlyForUnknownSourcesAndNotMoreThanEvery30Seconds() {
        let own: [UInt8] = [192, 168, 8, 2]
        let other: [UInt8] = [192, 168, 8, 178]
        var tracker = OwnAddressTracker(addresses: [own], at: received)
        #expect(tracker.needsRefresh(for: own, at: received.addingTimeInterval(600)) == false)
        #expect(tracker.needsRefresh(for: other, at: received.addingTimeInterval(29)) == false)
        #expect(tracker.needsRefresh(for: other, at: received.addingTimeInterval(30)) == true)

        tracker.update([own, other], at: received.addingTimeInterval(30))
        #expect(tracker.addresses == [own, other])
        #expect(tracker.lastRefresh == received.addingTimeInterval(30))
        #expect(tracker.needsRefresh(for: [10, 0, 0, 1], at: received.addingTimeInterval(45)) == false)
        #expect(tracker.needsRefresh(for: [10, 0, 0, 1], at: received.addingTimeInterval(61)) == true)
    }

    @Test func emptyTrackerRefreshesOnFirstUnknownSource() {
        let tracker = OwnAddressTracker()
        #expect(tracker.addresses.isEmpty)
        #expect(tracker.needsRefresh(for: [1, 2, 3, 4], at: received) == true)
    }

    @Test func selectionKeepsWiFiAndHotspotBridgeOnly() {
        let selected = BSDMDNSListener.selectInterfaces(hotspotPhone)
        #expect(selected.map(\.name) == ["en0", "bridge100"])
        #expect(selected.first?.index == 13)
        #expect(selected.first?.ipv4Bytes == [192, 168, 8, 123])
        #expect(selected.last?.functionalType == InterfaceFunctionalType.unknown)
    }

    @Test func selectionKeepsUSBEthernetAfterWiFi() {
        let usb = descriptor("en3", index: 21, type: InterfaceFunctionalType.wired, addresses: [[10, 0, 1, 7]])
        let selected = BSDMDNSListener.selectInterfaces([usb] + hotspotPhone)
        #expect(selected.map(\.name) == ["en0", "en3", "bridge100"])
    }

    @Test func selectionDropsPointToPointDownAndAddressless() {
        let ptp = descriptor("en5", index: 30, flags: up | IFF_POINTOPOINT, type: InterfaceFunctionalType.wired, addresses: [[10, 0, 2, 1]])
        let down = descriptor("en6", index: 31, flags: IFF_BROADCAST | IFF_MULTICAST, type: InterfaceFunctionalType.wired, addresses: [[10, 0, 3, 1]])
        let noMulticast = descriptor("en7", index: 32, flags: IFF_UP | IFF_RUNNING, type: InterfaceFunctionalType.wired, addresses: [[10, 0, 4, 1]])
        let bare = descriptor("en8", index: 33, type: InterfaceFunctionalType.wired, addresses: [])
        let noIndex = descriptor("en9", index: 0, type: InterfaceFunctionalType.wired, addresses: [[10, 0, 5, 1]])
        #expect(BSDMDNSListener.selectInterfaces([ptp, down, noMulticast, bare, noIndex]).isEmpty)
    }

    @Test func selectionKeepsIPv6OnlyInterfaceWithoutIPv4() {
        let v6Only = descriptor("en2", index: 22, type: InterfaceFunctionalType.wired, addresses: [linkLocal])
        let selected = BSDMDNSListener.selectInterfaces([v6Only])
        #expect(selected.map(\.name) == ["en2"])
        #expect(selected.first?.ipv4 == nil)
        #expect(selected.first?.addresses == [linkLocal])
    }

    @Test func selectionWithUnknownFunctionalTypeFallsBackToFlagsAndNamePrefix() {
        let wifi = descriptor("en0", index: 13, type: nil, addresses: [[192, 168, 8, 123]])
        let awdl = descriptor("awdl0", index: 15, type: nil, addresses: [linkLocal])
        let llw = descriptor("llw0", index: 16, type: nil, addresses: [linkLocal])
        #expect(BSDMDNSListener.selectInterfaces([awdl, wifi, llw]).map(\.name) == ["en0"])
    }

    @Test func selectionDedupesByNameAndMergesAddresses() {
        let a = descriptor("en0", index: 13, type: InterfaceFunctionalType.wifiInfra, addresses: [[192, 168, 8, 123]])
        let b = descriptor("en0", index: 13, type: InterfaceFunctionalType.wifiInfra, addresses: [linkLocal, [192, 168, 8, 123]])
        let selected = BSDMDNSListener.selectInterfaces([a, b])
        #expect(selected.count == 1)
        #expect(selected.first?.addresses == [[192, 168, 8, 123], linkLocal])
    }

    @Test func noInterfacesYieldsLookupFailure() {
        #expect(BSDMDNSListener.selectInterfaces([]).isEmpty)
        let meta = MDNSListenerMeta.dictionary(interfaces: [], stats: MDNSListenerStats())
        #expect((meta["status"] as? String)?.hasPrefix("failed: interface lookup errno 6") == true)
        #expect(meta["interfaceName"] as? String == "")
        #expect(meta["interfaceIndex"] as? Int == 0)
        #expect((meta["interfaces"] as? [[String: Any]])?.isEmpty == true)
        #expect((meta["listenAddresses"] as? [String])?.isEmpty == true)
        #expect(MDNSListenerMeta.statusSummary([]).hasPrefix("failed: interface lookup errno 6"))
    }

    @Test func ownAddressesAreTheUnionOfSelectedInterfaces() {
        let selected = BSDMDNSListener.selectInterfaces(hotspotPhone)
        let union = BSDMDNSListener.addressUnion(selected)
        #expect(union == [[192, 168, 8, 123], linkLocal, [172, 20, 10, 1]])
        #expect(!union.contains([10, 20, 30, 40]) && !union.contains([127, 0, 0, 1]))
    }

    @Test func perInterfaceStatusesAreIndependentInMetaAndSummary() {
        var en0 = MDNSInterfaceReport(name: "en0", index: 13, functionalType: InterfaceFunctionalType.wifiInfra,
                                      status: .listening(interface: "en0", index: 13), ipv6Status: .listening(interface: "en0", index: 13))
        let bridge = MDNSInterfaceReport(name: "bridge100", index: 20, functionalType: InterfaceFunctionalType.unknown,
                                         status: .failed(stage: "IP_ADD_MEMBERSHIP", errno: 49), ipv6Status: .failed(stage: "IPV6_JOIN_GROUP", errno: 49))
        let v6Only = MDNSInterfaceReport(name: "en3", index: 21, functionalType: InterfaceFunctionalType.wired,
                                         status: .unavailable(reason: "no IPv4 address on en3"), ipv6Status: .listening(interface: "en3", index: 21))
        en0.recordDelivered(MDNSDatagram(payload: Data([0]), source: [10, 0, 0, 1], destination: [224, 0, 0, 251], sourcePort: 5353, destinationPort: 5353,
                                         ttl: 255, trafficClass: 0, timestamp: received))
        let meta = MDNSListenerMeta.dictionary(interfaces: [en0, bridge, v6Only], stats: MDNSListenerStats())
        #expect(meta["status"] as? String == "listening on en0 (ifindex 13)")
        #expect(meta["interfaceName"] as? String == "en0")
        #expect(meta["interfaceIndex"] as? Int == 13)
        #expect(meta["listenAddresses"] as? [String] == ["224.0.0.251:5353", "[ff02::fb]:5353"])
        let rows = meta["interfaces"] as? [[String: Any]]
        #expect(rows?.count == 3)
        #expect(rows?[0]["functionalType"] as? String == "wifiInfra")
        #expect(rows?[0]["frames"] as? Int == 1 && rows?[0]["ipv4Frames"] as? Int == 1)
        #expect(rows?[1]["name"] as? String == "bridge100")
        #expect((rows?[1]["status"] as? String)?.hasPrefix("failed: IP_ADD_MEMBERSHIP errno 49") == true)
        #expect(rows?[2]["status"] as? String == "unavailable: no IPv4 address on en3")
        #expect(rows?[2]["ipv6Status"] as? String == "listening on en3 (ifindex 21)")
        let summary = MDNSListenerMeta.statusSummary([en0, bridge, v6Only])
        #expect(summary.hasPrefix("listening on en0 (ifindex 13), en3 (ifindex 21); bridge100 failed: IP_ADD_MEMBERSHIP errno 49"))
    }

    @Test func summaryMarksIPv6OnlyAndFallsBackToTheFailure() {
        let v6 = MDNSInterfaceReport(name: "en0", index: 13, functionalType: nil,
                                     status: .unavailable(reason: "no IPv4 address on en0"), ipv6Status: .listening(interface: "en0", index: 13))
        #expect(MDNSListenerMeta.statusSummary([v6]) == "listening on en0 (ifindex 13), IPv6 only")
        let v4Failed = MDNSInterfaceReport(name: "en0", index: 13, functionalType: nil,
                                           status: .failed(stage: "bind", errno: 48), ipv6Status: .failed(stage: "bind6", errno: 48))
        #expect(MDNSListenerMeta.statusSummary([v4Failed]).hasPrefix("failed: bind errno 48"))
        let v6Failed = MDNSInterfaceReport(name: "en0", index: 13, functionalType: nil,
                                           status: .unavailable(reason: "no IPv4 address on en0"), ipv6Status: .failed(stage: "bind6", errno: 48))
        #expect(MDNSListenerMeta.statusSummary([v6Failed]).hasPrefix("failed: bind6 errno 48"))
    }

    @Test func functionalTypeNamesMatchTheHeaderValues() {
        #expect(InterfaceFunctionalType.wifiAWDL == UInt32(IFRTYPE_FUNCTIONAL_WIFI_AWDL))
        #expect(InterfaceFunctionalType.intcoproc == UInt32(IFRTYPE_FUNCTIONAL_INTCOPROC))
        #expect(InterfaceFunctionalType.wifiInfra == UInt32(IFRTYPE_FUNCTIONAL_WIFI_INFRA))
        #expect(InterfaceFunctionalType.name(3) == "wifiInfra")
        #expect(InterfaceFunctionalType.name(nil) == "unavailable")
        #expect(InterfaceFunctionalType.name(42) == "other(42)")
        #expect(MemoryLayout<ifreq>.size == 32)
    }

    @Test func interfaceAddressesReadsLoopback() {
        let addresses = BSDMDNSListener.interfaceAddresses(named: "lo0")
        #expect(addresses?.contains([127, 0, 0, 1]) == true)
        #expect(BSDMDNSListener.interfaceAddresses(named: "nosuch99") == [])
        #expect(BSDMDNSListener.interfaceAddresses(named: ["lo0", "nosuch99"])?.contains([127, 0, 0, 1]) == true)
    }

    @Test func interfaceDescriptorsIncludeLoopbackWithItsFunctionalType() {
        let lo = BSDMDNSListener.interfaceDescriptors().first { $0.name == "lo0" }
        #expect((lo?.flags ?? 0) & IFF_LOOPBACK != 0)
        #expect(lo?.addresses.contains([127, 0, 0, 1]) == true)
        #expect(lo?.functionalType == InterfaceFunctionalType.loopback)
        #expect(BSDMDNSListener.captureInterfaces().allSatisfy { $0.name != "lo0" })
    }

    @Test func datagramCarriesTrafficClassFromControlMessages() {
        var cmsgs = MDNSControlMessages()
        cmsgs.trafficClass = 0x48
        let d = BSDMDNSListener.makeDatagram(sourceAddress: sockaddr4([10, 0, 0, 9], port: 5353), payload: Data([0]), cmsgs: cmsgs, received: received)
        #expect(d?.trafficClass == 0x48)
        let none = BSDMDNSListener.makeDatagram(sourceAddress: sockaddr6([UInt8](repeating: 1, count: 16), port: 5353),
                                                payload: Data([0]), cmsgs: MDNSControlMessages(), received: received)
        #expect(none?.trafficClass == nil)
    }

    @Test func recordDeliveredCountsFamilyOwnershipAndFallbacks() {
        var stats = MDNSListenerStats()
        let full = MDNSDatagram(payload: Data([0]), source: [10, 0, 0, 1], destination: [224, 0, 0, 251], sourcePort: 5353, destinationPort: 5353,
                                ttl: 255, trafficClass: 0, timestamp: received)
        let bare = MDNSDatagram(payload: Data([0]), source: [UInt8](repeating: 1, count: 16), destination: group6, sourcePort: 5353, destinationPort: 5353,
                                ttl: nil, trafficClass: nil, timestamp: received)
        stats.recordDelivered(full, own: true, kernelStamped: true)
        stats.recordDelivered(bare, own: false, kernelStamped: false)
        #expect(stats.frames == 2)
        #expect(stats.ipv4Frames == 1 && stats.ipv6Frames == 1)
        #expect(stats.ownFrames == 1)
        #expect(stats.kernelStamped == 1)
        #expect(stats.ttlMissing == 1)
        #expect(stats.tosMissing == 1)
    }

    @Test func metaReportsEveryDropAndTheReceivedTotal() {
        var stats = MDNSListenerStats()
        stats.datagramsReceived = 10; stats.frames = 6; stats.droppedTruncated = 2; stats.droppedUndecodable = 1; stats.droppedUnbuildable = 1
        stats.controlTruncatedFrames = 3; stats.ownAddressRefreshes = 4; stats.ttlMissing = 2; stats.kernelStamped = 5; stats.interfaceMismatchFrames = 1
        let meta = meta(status: .listening(interface: "en0", index: 13), ipv6Status: .idle, stats: stats)
        #expect(meta["framesReceived"] as? Int == 10)
        #expect(meta["interfaceMismatchFrames"] as? Int == 1)
        #expect(meta["frames"] as? Int == 6)
        #expect(meta["droppedTruncated"] as? Int == 2)
        #expect(meta["truncatedFrames"] as? Int == 2)
        #expect(meta["droppedUndecodable"] as? Int == 1)
        #expect(meta["droppedUnbuildable"] as? Int == 1)
        #expect(meta["controlTruncatedFrames"] as? Int == 3)
        #expect(meta["ownAddressRefreshes"] as? Int == 4)
        #expect(meta["ttlFallbackFrames"] as? Int == 2)
        #expect(meta["wallclockFallbackFrames"] as? Int == 1)
        let accounted = (meta["frames"] as? Int ?? 0) + (meta["droppedTruncated"] as? Int ?? 0)
            + (meta["droppedUndecodable"] as? Int ?? 0) + (meta["droppedUnbuildable"] as? Int ?? 0)
        #expect(meta["framesReceived"] as? Int == accounted)
    }

    @Test func tosSourceReportsReceivedFixedAndNotApplicable() {
        func source(frames: Int, missing: Int) -> String? {
            var stats = MDNSListenerStats()
            stats.frames = frames; stats.tosMissing = missing
            return meta(status: .idle, ipv6Status: .idle, stats: stats)["tosSource"] as? String
        }
        #expect(source(frames: 0, missing: 0) == "n/a")
        #expect(source(frames: 5, missing: 0) == "received")
        #expect(source(frames: 5, missing: 3) == "fixed-0 for 3")
    }

    @Test func notStartedMetaCarriesAnExplicitStatusThatIsNotListening() {
        let status = MDNSListenerMeta.notStartedStatus
        #expect(status == "not started (tunnel stopped before startup)")
        let meta = MDNSListenerMeta.dictionary(notStarted: status)
        #expect(meta["status"] as? String == status)
        #expect(meta["ipv6Status"] as? String == status)
        #expect((meta["interfaces"] as? [Any])?.isEmpty == true)
        #expect(meta["frames"] as? Int == 0)
        // The app's empty state must not read it as a listening interface.
        #expect(MDNSEmptyState.interfaceNames(from: status).isEmpty)
        #expect(MDNSEmptyState.text(isCapturing: true, filterOn: true, listenerStatus: status).contains("could not start"))
    }

    @Test func metaListsTheSynthesizedFieldsAndTheDisclaimerNamesThem() {
        let meta = meta(status: .idle, ipv6Status: .idle)
        #expect(meta["synthesizedFields"] as? [String] == ["ipv4.identification", "ipv4.flags", "ipv6.flowLabel", "ipv4.headerChecksum", "udp.checksum", "linkLayerHeader"])
        let text = MDNSListenerMeta.disclaimerSentence
        #expect(text.contains("TOS/traffic class are from the wire"))
        #expect(text.contains("IPv4 identification (0), flags (DF), IPv6 flow label (0), and both checksums (recomputed) are synthesized"))
        #expect(text.contains("no link-layer header"))
    }

    // MARK: - LAN route (S6)

    @Test func lanRouteFollowsTheListenerRankingAndReducesToTheNetwork() {
        let route = LANRouteSelection.route(from: hotspotPhone)
        #expect(route?.interfaceName == "en0")
        #expect(route?.addressText == "192.168.8.123")
        #expect(route?.networkText == "192.168.8.0")
        #expect(route?.netmaskText == "255.255.255.0")
        #expect(route?.networkAddress == [192, 168, 8, 0])
    }

    @Test func lanRouteSkipsLinkLocalAndAddresslessInterfaces() {
        // Field case: Wi-Fi wins; the USB link's 169.254 address is never a LAN route even when Wi-Fi has no IPv4.
        #expect(LANRouteSelection.route(from: cabledPhone)?.interfaceName == "en0")
        var wifiV6Only = cabledPhone
        wifiV6Only[0] = descriptor("en0", index: 13, type: InterfaceFunctionalType.wifiInfra, addresses: [linkLocal])
        #expect(LANRouteSelection.route(from: wifiV6Only) == nil)
        // A wired interface with a routable address is next in line once Wi-Fi has none.
        let ethernet = descriptor("en3", index: 23, type: InterfaceFunctionalType.wired, addresses: [[10, 0, 1, 7]], netmasks: [[10, 0, 1, 7]: [255, 255, 0, 0]])
        let route = LANRouteSelection.route(from: wifiV6Only + [ethernet])
        #expect(route?.interfaceName == "en3")
        #expect(route?.networkText == "10.0.0.0")
        #expect(route?.netmaskText == "255.255.0.0")
        #expect(LANRouteSelection.isLinkLocal([169, 254, 0, 1]) && !LANRouteSelection.isLinkLocal([169, 253, 0, 1]) && !LANRouteSelection.isLinkLocal(linkLocal))
    }

    @Test func lanRouteNeedsARunningInterfaceWithAWellFormedNetmask() {
        let notRunning = descriptor("en0", index: 13, flags: IFF_UP | IFF_BROADCAST | IFF_MULTICAST, type: InterfaceFunctionalType.wifiInfra,
                                    addresses: [[192, 168, 8, 123]], netmasks: [[192, 168, 8, 123]: slash24])
        #expect(LANRouteSelection.route(from: [notRunning]) == nil)
        let noMask = descriptor("en0", index: 13, type: InterfaceFunctionalType.wifiInfra, addresses: [[192, 168, 8, 123]])
        #expect(LANRouteSelection.route(from: [noMask]) == nil)
        let shortMask = descriptor("en0", index: 13, type: InterfaceFunctionalType.wifiInfra, addresses: [[192, 168, 8, 123]], netmasks: [[192, 168, 8, 123]: [255, 255]])
        #expect(LANRouteSelection.route(from: [shortMask]) == nil)
        // A second IPv4 alias with a netmask is used when the first has none.
        let alias = descriptor("en0", index: 13, type: InterfaceFunctionalType.wifiInfra, addresses: [[192, 168, 8, 123], [10, 9, 8, 7]], netmasks: [[10, 9, 8, 7]: slash24])
        #expect(LANRouteSelection.route(from: [alias])?.networkText == "10.9.8.0")
    }

    @Test func lanRouteNeverPicksLoopbackCellularOrTheTunnel() {
        let noLAN = hotspotPhone.filter { !["en0", "bridge100"].contains($0.name) }
        #expect(LANRouteSelection.route(from: noLAN) == nil)
        #expect(LANRouteSelection.route(from: []) == nil)
        // With Wi-Fi gone the hotspot bridge is the only LAN left and is used as such.
        let hotspotOnly = hotspotPhone.filter { $0.name != "en0" }
        #expect(LANRouteSelection.route(from: hotspotOnly)?.interfaceName == "bridge100")
        #expect(LANRouteSelection.route(from: hotspotOnly)?.networkText == "172.20.10.0")
    }

    @Test func lanRouteReadsNetmasksAcrossDuplicateDescriptors() {
        let v6Entry = descriptor("en0", index: 13, type: InterfaceFunctionalType.wifiInfra, addresses: [linkLocal])
        let v4Entry = descriptor("en0", index: 13, type: InterfaceFunctionalType.wifiInfra, addresses: [[192, 168, 8, 123]], netmasks: [[192, 168, 8, 123]: slash24])
        #expect(LANRouteSelection.route(from: [v6Entry, v4Entry])?.networkText == "192.168.8.0")
        let merged = BSDMDNSListener.selectInterfaces([v6Entry, v4Entry])
        #expect(merged.count == 1 && merged.first?.ipv4Bytes == [192, 168, 8, 123])
    }

    @Test func interfaceDescriptorsCarryTheLoopbackNetmask() {
        let lo = BSDMDNSListener.interfaceDescriptors().first { $0.name == "lo0" }
        #expect(lo?.ipv4Netmasks[[127, 0, 0, 1]] == [255, 0, 0, 0])
    }

    // MARK: - Interface reconcile (N6)

    @Test func reconcileOpensAnInterfaceThatAppeared() {
        let active = [report("en0", index: 13, type: InterfaceFunctionalType.wifiInfra)]
        let bridge = capture("bridge100", index: 20, type: InterfaceFunctionalType.unknown, addresses: [[172, 20, 10, 1], linkLocal])
        let changes = BSDMDNSListener.interfaceChanges(active: active, selected: [capture("en0", index: 13, addresses: [[192, 168, 8, 123]]), bridge])
        #expect(changes.added == [bridge])
        #expect(changes.removed.isEmpty && changes.ipv4Appeared.isEmpty)
        #expect(!changes.isEmpty)
    }

    @Test func reconcileClosesAnInterfaceThatVanished() {
        let bridge = report("bridge100", index: 20, type: InterfaceFunctionalType.unknown)
        let active = [report("en0", index: 13, type: InterfaceFunctionalType.wifiInfra), bridge]
        let changes = BSDMDNSListener.interfaceChanges(active: active, selected: [capture("en0", index: 13, addresses: [[192, 168, 8, 123]])])
        #expect(changes.removed == [bridge])
        #expect(changes.added.isEmpty && changes.ipv4Appeared.isEmpty)
    }

    @Test func reconcileTreatsANewIndexAsRemoveThenAdd() {
        let old = report("bridge100", index: 20, type: InterfaceFunctionalType.unknown)
        let new = capture("bridge100", index: 21, type: InterfaceFunctionalType.unknown, addresses: [[172, 20, 10, 1]])
        let changes = BSDMDNSListener.interfaceChanges(active: [old], selected: [new])
        #expect(changes.removed == [old])
        #expect(changes.added == [new])
    }

    @Test func reconcileIgnoresReportsAlreadyRemoved() {
        var gone = report("bridge100", index: 20, type: InterfaceFunctionalType.unknown)
        gone.markRemoved()
        let en0 = report("en0", index: 13, type: InterfaceFunctionalType.wifiInfra)
        let steady = BSDMDNSListener.interfaceChanges(active: [en0, gone], selected: [capture("en0", index: 13, addresses: [[192, 168, 8, 123]])])
        #expect(steady.isEmpty)
        // The same name and index coming back is a fresh interface, not the removed report.
        let back = capture("bridge100", index: 20, type: InterfaceFunctionalType.unknown, addresses: [[172, 20, 10, 1]])
        let returned = BSDMDNSListener.interfaceChanges(active: [en0, gone], selected: [capture("en0", index: 13, addresses: [[192, 168, 8, 123]]), back])
        #expect(returned.added == [back] && returned.removed.isEmpty)
    }

    @Test func reconcileOpensIPv4OnceAnAddressArrives() {
        let waiting = report("en3", index: 23, status: .unavailable(reason: "no IPv4 address on en3"))
        let withV4 = capture("en3", index: 23, addresses: [linkLocal, [10, 0, 1, 7]])
        #expect(BSDMDNSListener.interfaceChanges(active: [waiting], selected: [withV4]).ipv4Appeared == [withV4])
        // Still no address, or a real failure, leaves the interface alone.
        let stillV6 = capture("en3", index: 23, addresses: [linkLocal])
        #expect(BSDMDNSListener.interfaceChanges(active: [waiting], selected: [stillV6]).isEmpty)
        let failed = report("en3", index: 23, status: .failed(stage: "bind", errno: 48))
        #expect(BSDMDNSListener.interfaceChanges(active: [failed], selected: [withV4]).isEmpty)
    }

    @Test func reconcileWithNoDifferenceIsEmpty() {
        let selected = BSDMDNSListener.selectInterfaces(hotspotPhone)
        let active = selected.map { report($0.name, index: $0.index, type: $0.functionalType) }
        #expect(BSDMDNSListener.interfaceChanges(active: active, selected: selected).isEmpty)
        #expect(BSDMDNSListener.interfaceChanges(active: [], selected: []).isEmpty)
        #expect(BSDMDNSListener.interfaceChanges(active: [], selected: selected).added == selected)
    }

    @Test func removedReportKeepsItsCountersAndLeavesThePrimaryRole() {
        var en0 = report("en0", index: 13, type: InterfaceFunctionalType.wifiInfra)
        for _ in 0..<12 {
            en0.recordDelivered(MDNSDatagram(payload: Data([0]), source: [10, 0, 0, 1], destination: [224, 0, 0, 251], sourcePort: 5353, destinationPort: 5353,
                                             ttl: 255, trafficClass: 0, timestamp: received))
        }
        en0.markRemoved()
        #expect(en0.isRemoved && !en0.isListening)
        #expect(en0.frames == 12 && en0.ipv4Frames == 12)
        #expect(en0.status.description == "removed (interface went away)")
        #expect(en0.ipv6Status == .removed)

        let bridge = report("bridge100", index: 20, type: InterfaceFunctionalType.unknown)
        var stats = MDNSListenerStats()
        stats.interfaceChanges = 2
        let meta = MDNSListenerMeta.dictionary(interfaces: [en0, bridge], stats: stats)
        #expect(meta["interfaceName"] as? String == "bridge100")
        #expect(meta["interfaceIndex"] as? Int == 20)
        #expect(meta["status"] as? String == "listening on bridge100 (ifindex 20)")
        #expect(meta["interfaceChanges"] as? Int == 2)
        let rows = meta["interfaces"] as? [[String: Any]]
        #expect(rows?.count == 2)
        #expect(rows?[0]["status"] as? String == "removed (interface went away)")
        #expect(rows?[0]["frames"] as? Int == 12)

        let summary = MDNSListenerMeta.statusSummary([en0, bridge])
        #expect(summary == "listening on bridge100 (ifindex 20); en0 removed (interface went away)")
        #expect(MDNSEmptyState.interfaceNames(from: summary) == ["bridge100"])
        // Every interface gone: the primary falls back to the first ever selected and nothing is listening.
        var bridgeGone = bridge
        bridgeGone.markRemoved()
        #expect(MDNSListenerMeta.statusSummary([en0, bridgeGone]) == "removed (interface went away)")
        #expect(MDNSEmptyState.interfaceNames(from: MDNSListenerMeta.statusSummary([en0, bridgeGone])).isEmpty)
    }

    @Test func reconcileDelayCoalescesNotificationBursts() {
        #expect(BSDMDNSListener.reconcileDelay >= 0.5 && BSDMDNSListener.reconcileDelay <= 5)
    }
}
