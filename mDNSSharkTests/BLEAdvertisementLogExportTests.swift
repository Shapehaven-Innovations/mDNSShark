import Testing
import Foundation
import DeviceFingerprint
@testable import mDNSShark

@Suite("Advertisement log export") struct BLEAdvertisementLogExportTests {
    let parser = BLEAdvertisementParser(companies: BLECompanyTable(text: "76\tApple, Inc."), services: BLEServiceNameTable(text: ""))

    func record(name: String?, rssi: Int, at: Date) -> BLEAdvertisementRecord {
        let fields = BLEAdvertisementFields(localName: name, manufacturerData: Data([0x4C, 0x00, 0x10, 0x05]),
                                            serviceUUIDs: ["180F"], txPower: 4, isConnectable: true)
        let sighting = BLESighting(identifier: UUID(), fields: fields, rssi: rssi, at: at)
        return BLEAdvertisementRecord(sighting: sighting, parsed: parser.parse(fields), peripheralID: UUID())
    }

    var twoRecords: [BLEAdvertisementRecord] {
        [record(name: "Sonos, Roam", rssi: -61, at: Date(timeIntervalSince1970: 1_800_000_000.25)),
         record(name: nil, rssi: -80, at: Date(timeIntervalSince1970: 1_800_000_001.5))]
    }

    @Test func csvEscapesQuotesNewlinesAndFormulas() {
        #expect(BLEAdvertisementLogExport.csvField("Sonos, Roam") == "\"Sonos, Roam\"")
        #expect(BLEAdvertisementLogExport.csvField("He said \"hi\"") == "\"He said \"\"hi\"\"\"")
        #expect(BLEAdvertisementLogExport.csvField("line\nbreak") == "\"line\nbreak\"")
        #expect(BLEAdvertisementLogExport.csvField("=HYPERLINK(\"x\")") == "\"'=HYPERLINK(\"\"x\"\")\"")
        #expect(BLEAdvertisementLogExport.csvField("plain") == "plain")
    }

    @Test func csvHasHeaderAndOneLinePerRecord() {
        let csv = BLEAdvertisementLogExport.csv(twoRecords)
        #expect(csv.hasSuffix("\r\n"))
        let lines = csv.components(separatedBy: "\r\n").filter { !$0.isEmpty }
        #expect(lines.count == 3)
        #expect(lines[0] == BLEAdvertisementLogExport.csvHeader)
        #expect(lines[1].contains("\"Sonos, Roam\""))
        #expect(lines[1].contains(",-61,"))
    }

    @Test func jsonCarriesLabelAndRecords() throws {
        let data = try BLEAdvertisementLogExport.json(twoRecords)
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(object["label"] as? String == BLEAdvertisementLogExport.label)
        let records = try #require(object["records"] as? [[String: Any]])
        #expect(records.count == 2)
        #expect(records[0]["identifier"] == nil)
        let at = try #require(records[0]["at"] as? String)
        #expect(at.contains(".250"))
    }

    @Test func labelNeverSaysCapture() {
        #expect(BLEAdvertisementLogExport.label == "Advertisement log, not a link-layer capture")
    }

    @Test func purgeRemovesOnlyStaleExports() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("ble-purge-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        for name in ["mDNSShark-ble-advertisements-2026-11-08-070000.json", "mDNSShark-ble-advertisements-2026-11-08-070001.csv", "capture.pcap"] {
            try Data("x".utf8).write(to: dir.appendingPathComponent(name))
        }
        #expect(BLEAdvertisementLogExport.purgeStaleExports(in: dir) == 2)
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path) == ["capture.pcap"])
        #expect(BLEAdvertisementLogExport.writeOptions.contains(.completeFileProtection))
        #expect(BLEAdvertisementLogExport.writeOptions.contains(.atomic))
    }

    @Test func fileStemFormat() {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = .current
        let date = try! #require(calendar.date(from: DateComponents(year: 2026, month: 11, day: 8, hour: 9, minute: 5, second: 7)))
        #expect(BLEAdvertisementLogExport.fileStem(now: date) == "mDNSShark-ble-advertisements-2026-11-08-090507")
    }
}
