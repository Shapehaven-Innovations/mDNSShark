import XCTest
@testable import DeviceFingerprint

final class DataNoticeTests: XCTestCase {
    func test_everyBundledDataSourceIsCredited() {
        XCTAssertEqual(DataNotice.all.map(\.title), ["Bluetooth Numbers Database", "AppleDB", "Home Assistant", "xiaomi-ble"])
    }

    func test_licenseTextsShipInFull() {
        for notice in DataNotice.all {
            XCTAssertNotNil(Bundle.module.url(forResource: notice.licenseResource, withExtension: "txt"), notice.title)
            XCTAssertGreaterThan(notice.licenseText.count, 1000, notice.title)
        }
        let byTitle = Dictionary(uniqueKeysWithValues: DataNotice.all.map { ($0.title, $0) })
        XCTAssertTrue(byTitle["AppleDB"]!.licenseText.hasPrefix("MIT License"))
        XCTAssertTrue(byTitle["AppleDB"]!.licenseText.contains("Copyright (c) 2022 emiyl"))
        XCTAssertTrue(byTitle["Home Assistant"]!.licenseText.contains("Apache License"))
        XCTAssertTrue(byTitle["xiaomi-ble"]!.licenseText.contains("Copyright 2022 J. Nick Koston"))
        XCTAssertTrue(byTitle["Bluetooth Numbers Database"]!.licenseText.contains("Nordic Semiconductor ASA"))
    }
}
