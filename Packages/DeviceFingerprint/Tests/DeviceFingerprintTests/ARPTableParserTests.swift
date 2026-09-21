import XCTest
import Darwin
@testable import DeviceFingerprint

final class ARPTableParserTests: XCTestCase {
    // MARK: - Fixture construction
    //
    // Mirrors the real buffer `sysctl(CTL_NET, PF_ROUTE, 0, AF_INET,
    // NET_RT_FLAGS, RTF_LLINFO)` returns: a concatenation of one
    // `rt_msghdr` + address structs per ARP entry (the same shape `arp -a`
    // and `netstat -rn` decode). Built from the real Darwin-imported
    // structs (not hand-rolled offsets) so a layout mismatch here would
    // also break the production sysctl call, not just this fixture.

    private func roundedUp(_ len: Int) -> Int {
        len > 0 ? ((len - 1) | (MemoryLayout<UInt32>.size - 1)) + 1 : MemoryLayout<UInt32>.size
    }

    /// One synthetic ARP entry: `rt_msghdr` + `sockaddr_inarp` (RTA_DST,
    /// the neighbor's IPv4) + `sockaddr_dl` (RTA_GATEWAY, its link-layer
    /// address). `mac` nil or all-zero bytes simulates the iOS 18-26
    /// sandbox-zeroed case; a real 6-byte address simulates iOS 27+ with
    /// the entitlement granted.
    private func makeEntry(ip: (UInt8, UInt8, UInt8, UInt8), mac: [UInt8]?, llinfo: Bool = true) -> [UInt8] {
        var dst = sockaddr_inarp()
        dst.sin_len = UInt8(MemoryLayout<sockaddr_inarp>.size)
        dst.sin_family = sa_family_t(AF_INET)
        dst.sin_addr = in_addr(s_addr: UInt32(ip.0) | (UInt32(ip.1) << 8) | (UInt32(ip.2) << 16) | (UInt32(ip.3) << 24))
        let dstBytes = withUnsafeBytes(of: &dst) { Array($0) }

        let ifname: [UInt8] = Array("en0".utf8)
        let alen = mac?.count ?? 0
        var gatewayBytes: [UInt8] = [
            UInt8(8 + ifname.count + alen), // sdl_len
            UInt8(AF_LINK),                 // sdl_family
            0x00, 0x00,                     // sdl_index (u_short)
            6,                               // sdl_type (IFT_ETHER)
            UInt8(ifname.count),            // sdl_nlen
            UInt8(alen),                    // sdl_alen
            0                                // sdl_slen
        ]
        gatewayBytes += ifname
        gatewayBytes += mac ?? []
        while gatewayBytes.count < roundedUp(gatewayBytes.count) { gatewayBytes.append(0) }

        let addrsPadded = roundedUp(dstBytes.count) + gatewayBytes.count
        let headerSize = MemoryLayout<rt_msghdr>.size
        var header = rt_msghdr()
        header.rtm_msglen = UInt16(headerSize + addrsPadded)
        header.rtm_version = UInt8(RTM_VERSION)
        header.rtm_type = UInt8(RTM_GET)
        header.rtm_flags = llinfo ? Int32(RTF_LLINFO) : 0
        header.rtm_addrs = Int32(RTA_DST) | Int32(RTA_GATEWAY)
        let headerBytes = withUnsafeBytes(of: &header) { Array($0) }

        var out = headerBytes
        out += dstBytes
        while out.count < headerSize + roundedUp(dstBytes.count) { out.append(0) }
        out += gatewayBytes
        return out
    }

    // MARK: - roundedLength

    func test_roundedLength_roundsUpTo4ByteBoundary() {
        XCTAssertEqual(ARPTableParser.roundedLength(16), 16)
        XCTAssertEqual(ARPTableParser.roundedLength(17), 20)
        XCTAssertEqual(ARPTableParser.roundedLength(1), 4)
        XCTAssertEqual(ARPTableParser.roundedLength(0), 4)
    }

    // MARK: - parse

    func test_parse_resolvedEntry_decodesIPAndMAC() {
        let buffer = makeEntry(ip: (192, 168, 1, 1), mac: [0xAC, 0x22, 0x0B, 0x11, 0x22, 0x33])
        let entries = ARPTableParser.parse(Data(buffer))
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries[0].ipAddress, "192.168.1.1")
        XCTAssertEqual(entries[0].macAddress, "ac:22:0b:11:22:33")
    }

    func test_parse_zeroedMAC_simulatingPreiOS27Sandbox_macAddressIsNil() {
        let buffer = makeEntry(ip: (192, 168, 1, 2), mac: [0, 0, 0, 0, 0, 0])
        let entries = ARPTableParser.parse(Data(buffer))
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries[0].ipAddress, "192.168.1.2")
        XCTAssertNil(entries[0].macAddress)
    }

    func test_parse_incompleteARPEntry_noLinkLayerAddressYet_macAddressIsNil() {
        let buffer = makeEntry(ip: (192, 168, 1, 3), mac: nil)
        let entries = ARPTableParser.parse(Data(buffer))
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries[0].ipAddress, "192.168.1.3")
        XCTAssertNil(entries[0].macAddress)
    }

    func test_parse_multipleEntries_decodesAllIndependently() {
        var buffer = makeEntry(ip: (10, 0, 0, 1), mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        buffer += makeEntry(ip: (10, 0, 0, 2), mac: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB])
        let entries = ARPTableParser.parse(Data(buffer))
        XCTAssertEqual(entries.count, 2)
        XCTAssertEqual(entries[0].ipAddress, "10.0.0.1")
        XCTAssertEqual(entries[0].macAddress, "00:11:22:33:44:55")
        XCTAssertEqual(entries[1].ipAddress, "10.0.0.2")
        XCTAssertEqual(entries[1].macAddress, "66:77:88:99:aa:bb")
    }

    func test_parse_entryMissingLLINFOFlag_isFilteredOut() {
        // Defensive filter mirroring arp.c's own re-check of rtm_flags even
        // after requesting an already-filtered dump.
        let buffer = makeEntry(ip: (192, 168, 1, 9), mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], llinfo: false)
        let entries = ARPTableParser.parse(Data(buffer))
        XCTAssertTrue(entries.isEmpty)
    }

    func test_parse_emptyBuffer_returnsEmpty() {
        XCTAssertTrue(ARPTableParser.parse(Data()).isEmpty)
    }

    func test_parse_truncatedBuffer_shorterThanOneHeader_doesNotCrash() {
        let buffer: [UInt8] = [0x01, 0x02, 0x03]
        XCTAssertTrue(ARPTableParser.parse(Data(buffer)).isEmpty)
    }

    func test_parse_truncatedMessage_msgLenExceedsBufferBounds_stopsWithoutCrashing() {
        var buffer = makeEntry(ip: (192, 168, 1, 5), mac: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        buffer.removeLast(4) // truncate — rtm_msglen now overstates what's actually present
        XCTAssertTrue(ARPTableParser.parse(Data(buffer)).isEmpty)
    }
}
