import XCTest
@testable import DeviceFingerprint

final class UbiquitiDiscoveryPacketTests: XCTestCase {
    // version=2, type=0, len=13 header, then one TLV: type 0x0B "hostname"
    // (len=4) with value "test", then one TLV: type 0x01 "mac" (len=6) raw bytes.
    func test_decodesHostnameAndMacTLVs() {
        var bytes: [UInt8] = [0x02, 0x00, 0x00, 0x00] // version, type, len (patched below)
        var body: [UInt8] = []
        // hostname TLV
        body += [0x0B, 0x00, 0x04] + Array("test".utf8)
        // mac TLV (raw 6 bytes)
        body += [0x01, 0x00, 0x06] + [0x24, 0x5A, 0x4C, 0x01, 0x02, 0x03]
        let len = UInt16(body.count)
        bytes[2] = UInt8(len >> 8)
        bytes[3] = UInt8(len & 0xFF)
        bytes += body

        let reply = UbiquitiDiscoveryPacket.decode(Data(bytes))
        XCTAssertEqual(reply?.hostname, "test")
        XCTAssertEqual(reply?.mac, "24:5a:4c:01:02:03")
    }

    func test_truncatedPacket_returnsNilNotCrash() {
        XCTAssertNil(UbiquitiDiscoveryPacket.decode(Data([0x02, 0x00])))
    }

    func test_truncatedTLVValue_isIgnoredSafely() {
        // header says len=10 but only 3 bytes of TLV follow — must not crash.
        // With no other field parsed, decode must return nil for the WHOLE
        // reply (not just a nil hostname on a non-nil reply) — asserting on
        // the full optional distinguishes "nothing decoded" from "decoded
        // with an empty hostname field", which `?.hostname == nil` alone
        // cannot tell apart.
        let bytes: [UInt8] = [0x02, 0x00, 0x00, 0x0A, 0x0B, 0x00, 0xFF]
        XCTAssertNil(UbiquitiDiscoveryPacket.decode(Data(bytes)))
    }

    func test_emptyData_returnsNil() {
        XCTAssertNil(UbiquitiDiscoveryPacket.decode(Data()))
    }

    func test_probeV1_isFourBytes_01000000() {
        XCTAssertEqual(Array(UbiquitiDiscoveryPacket.probeV1()), [0x01, 0x00, 0x00, 0x00])
    }

    func test_probeV2_is0208_0000() {
        XCTAssertEqual(Array(UbiquitiDiscoveryPacket.probeV2()), [0x02, 0x08, 0x00, 0x00])
    }

    // MARK: - Additional fixture coverage (added in review-response round)

    /// Builds a well-formed packet: 4-byte header (version=2, type=0,
    /// len=BE16 of body) followed by the given TLVs (`type(1) len(2-BE)
    /// value`), in order.
    private func makePacket(_ tlvs: [(type: UInt8, value: [UInt8])]) -> Data {
        var bytes: [UInt8] = [0x02, 0x00, 0x00, 0x00]
        var body: [UInt8] = []
        for tlv in tlvs {
            let len = UInt16(tlv.value.count)
            body += [tlv.type, UInt8(len >> 8), UInt8(len & 0xFF)] + tlv.value
        }
        let len = UInt16(body.count)
        bytes[2] = UInt8(len >> 8)
        bytes[3] = UInt8(len & 0xFF)
        bytes += body
        return Data(bytes)
    }

    func test_unknownTLVType_followedByKnownTLV_skipsAndResyncs() {
        let data = makePacket([
            (type: 0xFE, value: [0xAA, 0xBB, 0xCC]), // unknown type, must be skipped
            (type: 0x0B, value: Array("known".utf8)) // hostname, must still be parsed
        ])
        let reply = UbiquitiDiscoveryPacket.decode(data)
        XCTAssertEqual(reply?.hostname, "known")
    }

    func test_goodTLV_followedByTruncatedTLV_earlierFieldIsPreserved() {
        // hostname TLV is well-formed and complete; the TLV after it claims
        // len=0xFF but no such data follows — the loop must stop there
        // WITHOUT discarding the hostname already parsed.
        var bytes: [UInt8] = [0x02, 0x00, 0x00, 0x00]
        var body: [UInt8] = []
        body += [0x0B, 0x00, 0x04] + Array("test".utf8) // complete hostname TLV
        body += [0x03, 0x00, 0xFF] // firmware TLV claiming 255 bytes that don't follow
        let len = UInt16(body.count)
        bytes[2] = UInt8(len >> 8)
        bytes[3] = UInt8(len & 0xFF)
        bytes += body

        let reply = UbiquitiDiscoveryPacket.decode(Data(bytes))
        XCTAssertEqual(reply?.hostname, "test")
        XCTAssertNil(reply?.firmware)
    }

    func test_macAndIPTLV_extractsFirstSixBytesAsMac() {
        let data = makePacket([
            (type: 0x02, value: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 192, 168, 1, 1])
        ])
        let reply = UbiquitiDiscoveryPacket.decode(data)
        XCTAssertEqual(reply?.mac, "00:11:22:33:44:55")
    }

    func test_macTLV_wrongByteLength_doesNotProduceGarbageMac() {
        let data = makePacket([
            (type: 0x0B, value: Array("host".utf8)), // keep reply non-nil
            (type: 0x01, value: [0x01, 0x02, 0x03, 0x04, 0x05]) // 5 bytes, not 6 — invalid
        ])
        let reply = UbiquitiDiscoveryPacket.decode(data)
        XCTAssertEqual(reply?.hostname, "host")
        XCTAssertNil(reply?.mac)
    }

    func test_macAndIPTLV_tooShort_doesNotProduceGarbageMac() {
        let data = makePacket([
            (type: 0x0B, value: Array("host".utf8)),
            (type: 0x02, value: [0x01, 0x02, 0x03, 0x04, 0x05]) // 5 bytes, needs >= 6
        ])
        let reply = UbiquitiDiscoveryPacket.decode(data)
        XCTAssertEqual(reply?.hostname, "host")
        XCTAssertNil(reply?.mac)
    }

    func test_firmwareModelSerial_areDecoded() {
        let data = makePacket([
            (type: 0x03, value: Array("1.2.3".utf8)),        // firmware
            (type: 0x14, value: Array("UAP-AC-PRO".utf8)),   // model (v1 TLV type)
            (type: 0x13, value: Array("SERIAL123".utf8))     // serial
        ])
        let reply = UbiquitiDiscoveryPacket.decode(data)
        XCTAssertEqual(reply?.firmware, "1.2.3")
        XCTAssertEqual(reply?.model, "UAP-AC-PRO")
        XCTAssertEqual(reply?.serial, "SERIAL123")
    }

    func test_modelV2TLVType_alsoDecodesAsModel() {
        let data = makePacket([
            (type: 0x15, value: Array("UDM-Pro".utf8)) // model (v2 TLV type)
        ])
        let reply = UbiquitiDiscoveryPacket.decode(data)
        XCTAssertEqual(reply?.model, "UDM-Pro")
    }

    func test_onlyUnknownTLVTypes_returnsNil() {
        let data = makePacket([
            (type: 0xFE, value: [0x01, 0x02]),
            (type: 0xFD, value: [0x03])
        ])
        XCTAssertNil(UbiquitiDiscoveryPacket.decode(data))
    }

    func test_nonUTF8BytesInHostnameTLV_fieldIsNilNotGarbage() {
        let data = makePacket([
            (type: 0x01, value: [0x24, 0x5A, 0x4C, 0x01, 0x02, 0x03]), // valid mac, keeps reply non-nil
            (type: 0x0B, value: [0xFF, 0xFE]) // invalid UTF-8 sequence
        ])
        let reply = UbiquitiDiscoveryPacket.decode(data)
        XCTAssertNotNil(reply)
        XCTAssertNil(reply?.hostname)
    }

    func test_macTLV_thenMacAndIPTLV_macTLVTakesPrecedence() {
        let data = makePacket([
            (type: 0x01, value: [0x24, 0x5A, 0x4C, 0x01, 0x02, 0x03]),                    // primary MAC
            (type: 0x02, value: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 10, 0, 0, 1])         // secondary interface MAC+IP
        ])
        let reply = UbiquitiDiscoveryPacket.decode(data)
        XCTAssertEqual(reply?.mac, "24:5a:4c:01:02:03")
    }
}
