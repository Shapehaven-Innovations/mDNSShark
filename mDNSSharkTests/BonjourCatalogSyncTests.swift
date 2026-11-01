import Foundation
import Testing
import DeviceFingerprint
@testable import mDNSShark

struct BonjourCatalogSyncTests {
    private var plistTypes: [String] {
        Bundle(for: NetworkScanner.self).object(forInfoDictionaryKey: "NSBonjourServices") as? [String] ?? []
    }

    @Test("every browsed type is declared in the Info.plist NSBonjourServices")
    func everyBrowseTypeIsDeclared() {
        let declared = Set(plistTypes)
        #expect(!declared.isEmpty)
        for type in NetworkScanner.serviceTypes { #expect(declared.contains(type), "\(type) missing from Info.plist") }
    }

    @Test("the plist has exactly one extra, the Local Network preflight type")
    func plistExtras() {
        #expect(Set(plistTypes).subtracting(NetworkScanner.serviceTypes) == ["_mdnssharklnp._tcp"])
    }

    @Test("the browse list has no duplicates and includes every catalog type")
    func noDuplicates() {
        #expect(Set(NetworkScanner.serviceTypes).count == NetworkScanner.serviceTypes.count)
        #expect(Set(BonjourTypeCatalog.browseTypes).isSubset(of: Set(NetworkScanner.serviceTypes)))
    }
}
