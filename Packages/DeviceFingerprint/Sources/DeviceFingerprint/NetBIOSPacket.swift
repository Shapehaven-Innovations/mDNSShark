import Foundation

public struct NetBIOSReply {
    public let mac: String?
    public let name: String?
}

/// Encoder/decoder for a NetBIOS Name Service NBSTAT query/response
/// (UDP port 137). The adapter-status reply's "unit ID" field is the
/// interface's MAC address — a source the Ubiquiti-focused probes don't
/// cover (Windows machines, many NAS boxes).
public enum NetBIOSPacket {
    public static func nbstatQuery() -> Data {
        var packet: [UInt8] = [
            0x82, 0x28, // transaction ID
            0x00, 0x00, // flags
            0x00, 0x01, // questions = 1
            0x00, 0x00, // answer RRs
            0x00, 0x00, // authority RRs
            0x00, 0x00  // additional RRs
        ]
        // Encoded name: "*" padded to 16 BYTES WITH NUL (0x00), not spaces —
        // the RFC 1001/1002 wildcard NBSTAT query name. Samba tolerates
        // space-padding (it trims trailing spaces), but Windows compares the
        // full 16-byte encoded name and may not answer at all to a
        // space-padded query — silently failing on exactly the platform
        // this probe exists to identify. `nbtstat`, `nmblookup`, and nmap's
        // `nbstat.nse` all send NUL padding.
        var nameBytes: [UInt8] = [UInt8(ascii: "*")]
        nameBytes += [UInt8](repeating: 0x00, count: 15)
        packet.append(0x20) // length prefix for encoded name
        for byte in nameBytes {
            packet.append(0x41 + (byte >> 4))
            packet.append(0x41 + (byte & 0x0F))
        }
        packet.append(0x00) // name terminator
        packet += [0x00, 0x21] // QTYPE = NBSTAT
        packet += [0x00, 0x01] // QCLASS = IN
        return Data(packet)
    }

    public static func decode(_ data: Data) -> NetBIOSReply? {
        let bytes = Array(data)
        // 12-byte header + 34-byte name + 10-byte TYPE/CLASS/TTL/RDLENGTH + 1-byte num_names
        guard bytes.count >= 57 else { return nil }

        // Cheap plausibility checks so a stray/malformed datagram can't be
        // misread as a valid NBSTAT reply just because its length happens
        // to line up: RCODE must indicate success, the reply must carry
        // exactly one answer RR, and that answer's TYPE must be NBSTAT
        // (0x0021).
        guard bytes[3] & 0x0F == 0x00 else { return nil }               // RCODE == 0
        guard bytes[6] == 0x00 && bytes[7] == 0x01 else { return nil }   // ANCOUNT == 1
        guard bytes[46] == 0x00 && bytes[47] == 0x21 else { return nil } // TYPE == NBSTAT

        // RFC 1002 §4.2.18 NODE_STATUS_RESPONSE: NUM_NAMES (1 byte, offset
        // 56) is followed by NUM_NAMES * 18-byte NODE_NAME entries, and ONLY
        // THEN the 6-byte UNIT_ID (MAC). A fixed offset is only correct when
        // NUM_NAMES == 0, which real hosts essentially never report (Windows
        // typically registers 3-7 names under multiple suffixes) — reading a
        // fixed offset against a real reply silently decodes bytes from
        // inside the host's own NetBIOS name as if they were a MAC address.
        let numNames = Int(bytes[56])
        let macOffset = 57 + 18 * numNames
        guard bytes.count >= macOffset + 6 else { return nil }
        let mac = bytes[macOffset..<macOffset + 6].map { String(format: "%02x", $0) }.joined(separator: ":")
        return NetBIOSReply(mac: mac, name: nil)
    }
}
