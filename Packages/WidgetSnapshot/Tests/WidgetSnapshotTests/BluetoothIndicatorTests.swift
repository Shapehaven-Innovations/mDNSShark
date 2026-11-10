import Testing
import Foundation
@testable import WidgetSnapshot

@Suite("Bluetooth indicator")
struct BluetoothIndicatorTests {
    let scan = Date(timeIntervalSince1970: 3_000_000)
    func summary(_ nearby: Int = 7) -> BluetoothSummary {
        BluetoothSummary(scannedAt: scan, nearby: nearby)
    }
    func model(_ nearby: Int = 7, after: Double = 720) -> BluetoothIndicatorModel? {
        BluetoothIndicatorModel.make(summary(nearby), now: scan.addingTimeInterval(after))
    }

    @Test("no summary draws nothing")
    func nilSummaryIsNil() {
        #expect(BluetoothIndicatorModel.make(nil, now: scan) == nil)
    }

    @Test("zero nearby draws nothing")
    func zeroNearbyIsNil() {
        #expect(model(0) == nil)
    }

    @Test("a Bluetooth scan 24 h or older is omitted")
    func omittedAt24h() {
        #expect(model(after: 86_400) == nil)
        #expect(model(after: 200_000) == nil)
        #expect(model(after: 86_399) != nil)
    }

    @Test("fresh at 29 minutes, stale at 30")
    func freshAt29MinStaleAt30Min() {
        #expect(model(after: 29 * 60)?.isStale == false)
        #expect(model(after: 30 * 60)?.isStale == true)
    }

    @Test("pill, line and security line exact strings")
    func lineTexts() {
        let m = model()!
        #expect(m.pillText == "7")
        #expect(m.ageText == "12 min ago")
        #expect(m.lineText == "7 nearby · 12 min ago")
        #expect(m.securityLineText == "7 nearby · not assessed · 12 min ago")
        #expect(m.accessibilityClause == "7 Bluetooth devices nearby, Bluetooth scanned 12 minutes ago")
        #expect(m.securityAccessibilityClause == m.accessibilityClause + ", not security assessed")
        #expect(m.lineTextWithoutAge == "7 nearby")
        #expect(m.securityLineTextWithoutAge == "7 nearby · not assessed")
        #expect(m.securityLineTextCompact == "7 · not assessed")
        #expect(m.pillCountText == "7")
    }

    @Test("one device reads singular")
    func singularClause() {
        #expect(model(1)!.accessibilityClause == "1 Bluetooth device nearby, Bluetooth scanned 12 minutes ago")
    }

    @Test("stale prefixes the clause and puts the age in the pill")
    func stalePrefixAndPill() {
        let m = model(after: 3 * 3600)!
        #expect(m.isStale)
        #expect(m.pillText == "7 · 3 hr ago")
        #expect(m.pillCountText == "7")
        #expect(m.accessibilityClause == "Bluetooth out of date, 7 Bluetooth devices nearby, Bluetooth scanned 3 hours ago")
    }

    @Test("between 30 and 60 minutes the age reads 30+ min so it is never under-reported before the hour mark",
          arguments: [1800.0, 2400, 3000, 3599])
    func stalePillBeforeTheHourReads30Plus(after: Double) {
        let m = model(after: after)!
        #expect(m.isStale)
        #expect(m.ageText == "30+ min ago")
        #expect(m.pillText == "7 · 30+ min ago")
        #expect(m.lineText == "7 nearby · 30+ min ago")
        #expect(m.securityLineText == "7 nearby · not assessed · 30+ min ago")
        #expect(m.accessibilityClause == "Bluetooth out of date, 7 Bluetooth devices nearby, Bluetooth scanned over 30 minutes ago")
    }

    @Test("from the hour mark the age is the ordinary hourly one")
    func stalePillAtTheHourReadsHours() {
        let m = model(after: 3600)!
        #expect(m.pillText == "7 · 1 hr ago")
        #expect(m.accessibilityClause.hasSuffix("Bluetooth scanned 1 hour ago"))
        #expect(model(after: 29 * 60)!.ageText == "29 min ago")
    }

    @Test("the symbol is the app's")
    func symbolConstant() {
        #expect(WidgetCopy.bluetoothSymbol == "wave.3.right")
    }
}
