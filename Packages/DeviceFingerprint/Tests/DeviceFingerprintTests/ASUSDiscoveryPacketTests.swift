import XCTest
@testable import DeviceFingerprint

final class ASUSDiscoveryPacketTests: XCTestCase {
    // MARK: - Fixture construction
    //
    // Wire format confirmed against ASUS's own GPL firmware source
    // (RMerl/asuswrt-merlin, an enhanced fork of the stock Asuswrt code):
    //   - release/src/router/shared/iboxcom.h (struct/enum definitions,
    //     `#pragma pack(1)` — no padding)
    //   - release/src/router/infosvr/common.c, `processPacket()` (shows
    //     exactly how NET_CMD_ID_GETINFO populates the reply)
    //
    // Reply layout (all integers little-endian, matching the 8-byte probe
    // `0C 15 1F 00 00 00 00 00` given in the task, which decodes cleanly as
    // ServiceID=0x0C, PacketType=0x15 (CMD), OpCode=0x001F (GETINFO,
    // little-endian), Info=0):
    //   offset 0   IBOX_COMM_PKT_RES header (8 bytes): ServiceID(1),
    //              PacketType(1)=0x16 (RES), OpCode(2 LE)=0x001F, Info(4 LE)
    //   offset 8   PrinterInfo[128]      (unused by us)
    //   offset 136 SSID[32]
    //   offset 168 NetMask[32]           (unused by us)
    //   offset 200 ProductID[32]         -> model
    //   offset 232 FirmwareVersion[16]
    //   offset 248 OperationMode[1]      (unused by us)
    //   offset 249 MacAddress[6]         (raw bytes, not a string)
    //   offset 255 sw_mode[1]            (unused by us)
    // Every string field is a NUL-terminated/zero-padded fixed-width C
    // string (`strcpy` into a BYTE[] in the original C).
    private func makeReply(
        serviceID: UInt8 = 0x0C,
        packetType: UInt8 = 0x16,
        opCodeLow: UInt8 = 0x1F,
        opCodeHigh: UInt8 = 0x00,
        ssid: String? = "MyHomeWiFi",
        productID: String? = "RT-AC68U",
        firmwareVersion: String? = "3.0.0.4.386_123",
        mac: [UInt8]? = [0xAC, 0x22, 0x0B, 0x11, 0x22, 0x33],
        totalLength: Int = 512
    ) -> Data {
        var bytes = [UInt8](repeating: 0, count: totalLength)
        bytes[0] = serviceID
        bytes[1] = packetType
        bytes[2] = opCodeLow
        bytes[3] = opCodeHigh
        // bytes[4...7] = Info, left as 0

        func writeCString(_ s: String?, at offset: Int, length: Int) {
            guard let s, offset + length <= bytes.count else { return }
            let strBytes = Array(s.utf8.prefix(length - 1)) // leave room for NUL
            for (i, b) in strBytes.enumerated() { bytes[offset + i] = b }
            // remaining bytes stay 0 (NUL padding)
        }
        writeCString(ssid, at: 136, length: 32)
        writeCString(productID, at: 200, length: 32)
        writeCString(firmwareVersion, at: 232, length: 16)
        if let mac, 249 + mac.count <= bytes.count {
            for (i, b) in mac.enumerated() { bytes[249 + i] = b }
        }
        return Data(bytes)
    }

    // MARK: - probe()

    // `infosvr.c`'s `processReq()` requires the request to be exactly
    // INFO_PDU_LENGTH (512) bytes — `iRcv = RECV(sockfd, pdubuf,
    // INFO_PDU_LENGTH, ...); if (iRcv != INFO_PDU_LENGTH) { closesocket(...);
    // return -1; }` — so an 8-byte-only probe is silently discarded by real
    // hardware. The wire header is still just the first 8 bytes; the rest
    // must be zero padding out to the full datagram size.
    func test_probe_is512BytesTotal_withGetInfoHeaderAndZeroPadding() {
        let probe = Array(ASUSDiscoveryPacket.probe())
        XCTAssertEqual(probe.count, 512)
        XCTAssertEqual(Array(probe.prefix(8)), [0x0C, 0x15, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00])
        XCTAssertTrue(probe.dropFirst(8).allSatisfy { $0 == 0 })
    }

    // MARK: - decode() happy path

    func test_decodesWellFormedReply() {
        let data = makeReply()
        let reply = ASUSDiscoveryPacket.decode(data)
        XCTAssertEqual(reply?.ssid, "MyHomeWiFi")
        XCTAssertEqual(reply?.model, "RT-AC68U")
        XCTAssertEqual(reply?.firmwareVersion, "3.0.0.4.386_123")
        XCTAssertEqual(reply?.mac, "ac:22:0b:11:22:33")
    }

    func test_decode_fieldsAtMaxFixedWidth_stillParsed() {
        // ProductID field is 32 bytes; a 31-char name plus NUL exactly fills it.
        let longModel = String(repeating: "X", count: 31)
        let data = makeReply(productID: longModel)
        XCTAssertEqual(ASUSDiscoveryPacket.decode(data)?.model, longModel)
    }

    // MARK: - decode() malformed/truncated input — must never crash, return nil

    func test_emptyData_returnsNil() {
        XCTAssertNil(ASUSDiscoveryPacket.decode(Data()))
    }

    func test_truncatedReply_shorterThanMacOffset_returnsNil() {
        // Only the header plus a partial PrinterInfo field — far short of
        // reaching the MAC field, must not crash indexing past the buffer.
        let bytes: [UInt8] = [0x0C, 0x16, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00] + [UInt8](repeating: 0, count: 10)
        XCTAssertNil(ASUSDiscoveryPacket.decode(Data(bytes)))
    }

    func test_truncatedReply_missingLastMacByte_returnsNil() {
        // One byte short of the minimum length needed to read all 6 MAC
        // bytes (offset 249..254 inclusive requires count >= 255).
        let full = makeReply(totalLength: 256)
        let oneShortOfMac = full.prefix(254)
        XCTAssertNil(ASUSDiscoveryPacket.decode(oneShortOfMac))
    }

    func test_wrongServiceID_returnsNil() {
        let data = makeReply(serviceID: 0xFF)
        XCTAssertNil(ASUSDiscoveryPacket.decode(data))
    }

    func test_wrongPacketType_returnsNil() {
        // e.g. a reflected CMD packet type (0x15) instead of a real RES (0x16)
        let data = makeReply(packetType: 0x15)
        XCTAssertNil(ASUSDiscoveryPacket.decode(data))
    }

    func test_wrongOpCode_returnsNil() {
        // Some other OpCode's reply shape, not GETINFO
        let data = makeReply(opCodeLow: 0x34, opCodeHigh: 0x00)
        XCTAssertNil(ASUSDiscoveryPacket.decode(data))
    }

    func test_allZeroMac_isNilNotGarbage() {
        let data = makeReply(mac: [0, 0, 0, 0, 0, 0])
        let reply = ASUSDiscoveryPacket.decode(data)
        XCTAssertNotNil(reply) // ssid/model/firmware are still present
        XCTAssertNil(reply?.mac)
    }

    func test_emptySSIDField_isNilNotEmptyString() {
        let data = makeReply(ssid: nil)
        let reply = ASUSDiscoveryPacket.decode(data)
        XCTAssertNil(reply?.ssid)
        XCTAssertEqual(reply?.model, "RT-AC68U") // other fields unaffected
    }

    func test_emptyProductIDField_isNilNotEmptyString() {
        let data = makeReply(productID: nil)
        let reply = ASUSDiscoveryPacket.decode(data)
        XCTAssertNil(reply?.model)
    }

    func test_emptyFirmwareVersionField_isNilNotEmptyString() {
        let data = makeReply(firmwareVersion: nil)
        let reply = ASUSDiscoveryPacket.decode(data)
        XCTAssertNil(reply?.firmwareVersion)
    }

    func test_allFieldsEmpty_returnsNil() {
        // If nothing decodable came back at all, the whole reply is nil —
        // same discipline as UbiquitiDiscoveryPacket: distinguishes "nothing
        // decoded" from "decoded with all-empty fields".
        let data = makeReply(ssid: nil, productID: nil, firmwareVersion: nil, mac: [0, 0, 0, 0, 0, 0])
        XCTAssertNil(ASUSDiscoveryPacket.decode(data))
    }

    func test_nonUTF8BytesInSSIDField_fieldIsNilNotGarbage_replyStillDecodes() {
        var bytes = Array(makeReply(ssid: nil))
        // invalid UTF-8 sequence in the SSID field
        bytes[136] = 0xFF
        bytes[137] = 0xFE
        let reply = ASUSDiscoveryPacket.decode(Data(bytes))
        XCTAssertNotNil(reply) // model/firmware/mac still present
        XCTAssertNil(reply?.ssid)
    }

    func test_nonZeroBytesAfterNULInField_areIgnored() {
        // The real firmware's response buffer is a persistent global that's
        // only memset to a pointer-sized number of bytes (a bug in the
        // original C), so bytes past a field's NUL terminator can be
        // leftover garbage from a PREVIOUS reply rather than zero padding.
        // The decoder must stop at the first NUL regardless.
        var bytes = Array(makeReply(ssid: "Hi"))
        // "Hi\0" occupies offsets 136-138; poison the rest of the 32-byte
        // SSID field (offsets 139-167) with non-zero "leftover" garbage.
        for i in 139..<168 { bytes[i] = 0xAB }
        let reply = ASUSDiscoveryPacket.decode(Data(bytes))
        XCTAssertEqual(reply?.ssid, "Hi")
    }
}
