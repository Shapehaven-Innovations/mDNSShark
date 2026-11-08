import Testing
import Foundation
@testable import WidgetSnapshot

@Suite("Bluetooth indicator")
struct BluetoothIndicatorTests {
    let scan = Date(timeIntervalSince1970: 3_000_000)
    func summary(_ nearby: Int = 7, _ suggested: Int = 2) -> BluetoothSummary {
        BluetoothSummary(scannedAt: scan, nearby: nearby, suggested: suggested)
    }
    func model(_ nearby: Int = 7, _ suggested: Int = 2, after: Double = 720) -> BluetoothIndicatorModel? {
        BluetoothIndicatorModel.make(summary(nearby, suggested), now: scan.addingTimeInterval(after))
    }

    @Test("no summary draws nothing")
    func nilSummaryIsNil() {
        #expect(BluetoothIndicatorModel.make(nil, now: scan) == nil)
    }

    @Test("zero nearby draws nothing")
    func zeroNearbyIsNil() {
        #expect(model(0, 0) == nil)
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
        #expect(m.lineText == "7 nearby · 2 suggested? · 12 min ago")
        #expect(m.securityLineText == "7 nearby · not assessed · 12 min ago")
        #expect(m.accessibilityClause == "7 Bluetooth devices nearby, 2 suggested as network devices, inferred, Bluetooth scanned 12 minutes ago")
        #expect(m.securityAccessibilityClause == m.accessibilityClause + ", not security assessed")
        #expect(m.lineTextWithoutAge == "7 nearby · 2 suggested?")
        #expect(m.lineTextNearbyAndAge == "7 nearby · 12 min ago")
        #expect(m.securityLineTextWithoutAge == "7 nearby · not assessed")
        #expect(m.lineTextCompact == "7 · 2 suggested?")
        #expect(m.securityLineTextCompact == "7 · not assessed")
        #expect(m.pillCountText == "7")
        #expect(model(7, 0)!.lineTextCompact == "7 nearby")
    }

    @Test("the suggested part is omitted when nothing is suggested")
    func suggestedPartOmittedWhenZero() {
        let m = model(7, 0)!
        #expect(m.lineText == "7 nearby · 12 min ago")
        #expect(m.accessibilityClause == "7 Bluetooth devices nearby, none suggested, Bluetooth scanned 12 minutes ago")
    }

    @Test("one device reads singular")
    func singularClause() {
        #expect(model(1, 1)!.accessibilityClause == "1 Bluetooth device nearby, 1 suggested as a network device, inferred, Bluetooth scanned 12 minutes ago")
    }

    @Test("stale prefixes the clause and puts the age in the pill")
    func stalePrefixAndPill() {
        let m = model(after: 3 * 3600)!
        #expect(m.isStale)
        #expect(m.pillText == "7 · 3 hr ago")
        #expect(m.pillCountText == "7")
        #expect(m.accessibilityClause == "Bluetooth out of date, 7 Bluetooth devices nearby, 2 suggested as network devices, inferred, Bluetooth scanned 3 hours ago")
    }

    @Test("the suggested count carries a question mark")
    func questionMarkOnSuggested() {
        #expect(WidgetCopy.suggested(2) == "2 suggested?")
    }

    @Test("the symbol is the app's")
    func symbolConstant() {
        #expect(WidgetCopy.bluetoothSymbol == "wave.3.right")
    }
}
