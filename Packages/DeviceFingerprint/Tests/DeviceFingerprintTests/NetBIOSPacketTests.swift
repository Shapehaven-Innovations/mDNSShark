import XCTest
@testable import DeviceFingerprint

final class NetBIOSPacketTests: XCTestCase {
    func test_queryIsWellFormedNBSTATRequest() {
        let query = NetBIOSPacket.nbstatQuery()
        // header (12 bytes) + encoded "*" name (34 bytes) + qtype/qclass (4 bytes) = 50
        XCTAssertEqual(query.count, 50)
        // question count field (bytes 4-5) must be 1
        XCTAssertEqual(query[4], 0x00)
        XCTAssertEqual(query[5], 0x01)
    }

    func test_queryNameField_encodesAsteriskWithNetBIOSFirstLevelEncoding() {
        let query = Array(NetBIOSPacket.nbstatQuery())
        // byte 12: length prefix for the encoded name (32 bytes = 0x20)
        XCTAssertEqual(query[12], 0x20)
        // "*" (0x2A) NetBIOS-first-level-encodes to nibbles 0x2/0xA -> 'C','K'
        XCTAssertEqual(query[13], 0x43) // 0x41 + 0x2
        XCTAssertEqual(query[14], 0x4B) // 0x41 + 0xA
        // The 15 trailing padding bytes must be NUL (0x00), NOT space
        // (0x20): the wildcard NBSTAT query name is "*" padded with NUL per
        // RFC 1001/1002, and real tools (nbtstat, nmblookup, nmap's
        // nbstat.nse) all send NUL padding. Windows compares the full
        // 16-byte encoded name and may silently not answer a space-padded
        // query at all, even though Samba tolerates it by trimming trailing
        // spaces. NUL (0x00) nibble-encodes to 0x41,0x41 ('A','A') — distinct
        // from space (0x20), which would encode to 0x43,0x41 ('C','A').
        for pairIndex in 1..<16 {
            let offset = 13 + pairIndex * 2
            XCTAssertEqual(query[offset], 0x41, "padding byte pair \(pairIndex) high nibble")
            XCTAssertEqual(query[offset + 1], 0x41, "padding byte pair \(pairIndex) low nibble")
        }
        // name terminator immediately after the 32 encoded bytes
        XCTAssertEqual(query[45], 0x00)
    }

    func test_queryEndsWithNBSTATQtypeAndINQclass() {
        let query = Array(NetBIOSPacket.nbstatQuery())
        XCTAssertEqual(query[46], 0x00)
        XCTAssertEqual(query[47], 0x21) // QTYPE = NBSTAT
        XCTAssertEqual(query[48], 0x00)
        XCTAssertEqual(query[49], 0x01) // QCLASS = IN
    }

    // MARK: - Reply fixture builder
    //
    // Assembles a well-formed-looking NBSTAT NODE STATUS RESPONSE:
    //   12-byte header (ANCOUNT=1, RCODE=0 — a real reply, not a stray
    //   datagram that merely happens to be the right length)
    // + 34-byte question/answer name field (content irrelevant — decode()
    //   never parses it)
    // + TYPE/CLASS/TTL/RDLENGTH (10 bytes; TYPE=NBSTAT=0x0021)
    // + NUM_NAMES (1 byte)
    // + whatever `afterNumNames` bytes the test supplies — the real reply
    //   has NUM_NAMES * 18-byte NODE_NAME entries there, THEN the 6-byte
    //   UNIT_ID (MAC), per RFC 1002 §4.2.18.
    private func makeReplyBytes(numNames: UInt8, afterNumNames: [UInt8]) -> [UInt8] {
        var bytes: [UInt8] = [
            0x82, 0x28, // transaction ID
            0x84, 0x00, // flags: response, authoritative, RCODE=0
            0x00, 0x00, // QDCOUNT = 0
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00  // ARCOUNT = 0
        ]
        bytes += [UInt8](repeating: 0, count: 34) // name field, not parsed by decode
        bytes += [0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x07] // TYPE=NBSTAT, CLASS=IN, TTL, RDLENGTH
        bytes += [numNames]
        bytes += afterNumNames
        return bytes
    }

    /// One 18-byte NODE_NAME entry: 15-byte space-padded printable name +
    /// 1 suffix byte + 2 NAME_FLAGS bytes.
    private func nodeNameEntry(_ name: String) -> [UInt8] {
        var nameBytes = Array(name.utf8)
        precondition(nameBytes.count <= 15)
        nameBytes += [UInt8](repeating: 0x20, count: 15 - nameBytes.count)
        return nameBytes + [0x00] + [0x00, 0x04] // suffix + NAME_FLAGS
    }

    func test_decodesMacFromAdapterStatusReply_withZeroRegisteredNames() {
        // NUM_NAMES = 0 is the boundary case where a fixed offset happens
        // to be correct — a real host essentially never reports this
        // (Windows typically registers 3-7 names), but it must still work.
        let bytes = makeReplyBytes(numNames: 0, afterNumNames: [0xFC, 0xEC, 0xDA, 0x01, 0x02, 0x03])
        let reply = NetBIOSPacket.decode(Data(bytes))
        XCTAssertEqual(reply?.mac, "fc:ec:da:01:02:03")
        // decode() never populates the name field — documented behavior, not
        // just an omission, so pin it down explicitly rather than leaving it
        // to whatever the struct's default happens to be.
        XCTAssertNil(reply?.name)
    }

    func test_decodesMacAfterMultipleNodeNameEntries_notFromInsideNames() {
        // The realistic case: NUM_NAMES = 2, two full 18-byte NODE_NAME
        // entries with distinct printable ASCII (so misreading bytes from
        // inside them would produce an obviously-wrong, recognizable MAC),
        // followed by the real 6-byte UNIT_ID, followed by trailing
        // statistics bytes the decoder must tolerate without misreading.
        var afterNumNames: [UInt8] = []
        afterNumNames += nodeNameEntry("DESKTOP-XYZ")
        afterNumNames += nodeNameEntry("WORKGROUP")
        let realMac: [UInt8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        afterNumNames += realMac
        afterNumNames += [UInt8](repeating: 0x11, count: 20) // trailing statistics, must be tolerated

        let bytes = makeReplyBytes(numNames: 2, afterNumNames: afterNumNames)
        let reply = NetBIOSPacket.decode(Data(bytes))
        XCTAssertEqual(reply?.mac, "aa:bb:cc:dd:ee:ff")
        // Sanity: this is NOT what you'd get from misreading the first 6
        // bytes of "DESKTOP-XYZ" as a MAC (0x44,0x45,0x53,0x4b,0x54,0x4f).
        XCTAssertNotEqual(reply?.mac, "44:45:53:4b:54:4f")
    }

    func test_implausibleNumNames_packetTooShortToContainThem_returnsNil() {
        // NUM_NAMES = 0xFF implies macOffset = 57 + 18*255 = 4647, but the
        // packet only has a handful of trailing bytes — must return nil,
        // not crash or read garbage.
        let bytes = makeReplyBytes(numNames: 0xFF, afterNumNames: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        XCTAssertNil(NetBIOSPacket.decode(Data(bytes)))
    }

    func test_truncatedPartwayThroughNodeNameArray_returnsNil() {
        // NUM_NAMES = 2 (so macOffset = 57 + 36 = 93 is expected), but the
        // packet ends partway through the very first 18-byte NODE_NAME
        // entry — must return nil, not read past the end or misinterpret
        // whatever partial bytes are present as the MAC.
        var afterNumNames = nodeNameEntry("PARTIAL")
        afterNumNames = Array(afterNumNames.prefix(10)) // truncate mid-entry
        let bytes = makeReplyBytes(numNames: 2, afterNumNames: afterNumNames)
        XCTAssertNil(NetBIOSPacket.decode(Data(bytes)))
    }

    func test_tooShortPacket_returnsNil() {
        XCTAssertNil(NetBIOSPacket.decode(Data([0x00, 0x01])))
    }

    func test_emptyData_returnsNil() {
        XCTAssertNil(NetBIOSPacket.decode(Data()))
    }

    func test_packetOneByteShortOfMacBoundary_returnsNil() {
        // NUM_NAMES = 0, so macOffset = 57; only 5 of the 6 MAC bytes present.
        let bytes = makeReplyBytes(numNames: 0, afterNumNames: [0xFC, 0xEC, 0xDA, 0x01, 0x02])
        XCTAssertNil(NetBIOSPacket.decode(Data(bytes)))
    }

    func test_packetExactlyAtMacBoundary_decodesSuccessfully() {
        // Exactly macOffset + 6 bytes — the tightest buffer that must still succeed.
        let bytes = makeReplyBytes(numNames: 0, afterNumNames: [0xFC, 0xEC, 0xDA, 0x01, 0x02, 0x03])
        let reply = NetBIOSPacket.decode(Data(bytes))
        XCTAssertEqual(reply?.mac, "fc:ec:da:01:02:03")
    }

    func test_allZeroMacBytes_decodesAsAllZeroMacString() {
        // Not a malformed-input case, but pins down that an all-zero unit ID
        // is decoded faithfully rather than being treated as "absent".
        let bytes = makeReplyBytes(numNames: 0, afterNumNames: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        let reply = NetBIOSPacket.decode(Data(bytes))
        XCTAssertEqual(reply?.mac, "00:00:00:00:00:00")
    }

    // MARK: - Plausibility-check coverage (added alongside the offset fix,
    // so the new guards against a stray/malformed datagram are pinned down
    // by tests rather than just asserted in a comment).

    func test_nonZeroRCODE_returnsNil() {
        var bytes = makeReplyBytes(numNames: 0, afterNumNames: [0xFC, 0xEC, 0xDA, 0x01, 0x02, 0x03])
        bytes[3] = 0x03 // RCODE = 3 (name error) — a failure response, not a real answer
        XCTAssertNil(NetBIOSPacket.decode(Data(bytes)))
    }

    func test_wrongANCOUNT_returnsNil() {
        var bytes = makeReplyBytes(numNames: 0, afterNumNames: [0xFC, 0xEC, 0xDA, 0x01, 0x02, 0x03])
        bytes[6] = 0x00
        bytes[7] = 0x00 // ANCOUNT = 0 — no answer RR present
        XCTAssertNil(NetBIOSPacket.decode(Data(bytes)))
    }

    func test_wrongTypeField_returnsNil() {
        var bytes = makeReplyBytes(numNames: 0, afterNumNames: [0xFC, 0xEC, 0xDA, 0x01, 0x02, 0x03])
        bytes[46] = 0x00
        bytes[47] = 0x01 // TYPE = A record, not NBSTAT
        XCTAssertNil(NetBIOSPacket.decode(Data(bytes)))
    }
}
