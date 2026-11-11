import Testing
import Foundation
@testable import mDNSShark

@Suite("Review request policy")
struct ReviewRequestPolicyTests {
    private let day: TimeInterval = 86_400
    private let start = Date(timeIntervalSince1970: 1_800_000_000)

    private func freshDefaults() -> UserDefaults {
        UserDefaults(suiteName: "ReviewRequestPolicyTests.\(UUID().uuidString)")!
    }

    /// A policy past the launch threshold unless told otherwise.
    private func policy(_ defaults: UserDefaults, version: String = "1.0", launches: Int = 5) -> ReviewRequestPolicy {
        let policy = ReviewRequestPolicy(defaults: defaults, appVersion: version)
        for _ in 0..<launches { policy.noteLaunch() }
        return policy
    }

    @Test("no ask before the fifth foreground launch")
    func launchThreshold() {
        let defaults = freshDefaults()
        let p = policy(defaults, launches: 0)
        #expect(!p.consumeRequest(isQuiet: true, now: start)) // brand-new install
        for _ in 0..<4 {
            p.noteLaunch()
            #expect(!p.consumeRequest(isQuiet: true, now: start))
        }
        #expect(defaults.object(forKey: ReviewRequestPolicy.Key.lastAskedDate) == nil)
        p.noteLaunch()
        #expect(p.consumeRequest(isQuiet: true, now: start))
    }

    @Test("not quiet records nothing, and the same moment asks once quiet")
    func quietGating() {
        let defaults = freshDefaults()
        let p = policy(defaults)
        #expect(p.isDue(now: start))
        #expect(!p.consumeRequest(isQuiet: false, now: start))
        #expect(defaults.object(forKey: ReviewRequestPolicy.Key.lastAskedDate) == nil)
        #expect(defaults.string(forKey: ReviewRequestPolicy.Key.lastAskedVersion) == nil)
        #expect(p.consumeRequest(isQuiet: true, now: start))
        #expect(!p.isDue(now: start))
    }

    @Test("quiet needs an active scene and every activity flag off")
    func quietComposition() {
        func quiet(scanning: Bool = false, bluetoothScanning: Bool = false, readingDeviceInfo: Bool = false,
                   tunnelActive: Bool = false, capturing: Bool = false, gateInFlight: Bool = false,
                   securityRefreshing: Bool = false, sceneActive: Bool = true) -> Bool {
            ReviewRequestPolicy.isQuiet(scanning: scanning, bluetoothScanning: bluetoothScanning,
                                        readingDeviceInfo: readingDeviceInfo, tunnelActive: tunnelActive,
                                        capturing: capturing, gateInFlight: gateInFlight,
                                        securityRefreshing: securityRefreshing, sceneActive: sceneActive)
        }
        #expect(quiet())
        #expect(!quiet(scanning: true))
        #expect(!quiet(bluetoothScanning: true))
        #expect(!quiet(readingDeviceInfo: true))
        #expect(!quiet(tunnelActive: true))
        #expect(!quiet(capturing: true))
        #expect(!quiet(gateInFlight: true))
        #expect(!quiet(securityRefreshing: true))
        #expect(!quiet(sceneActive: false))
    }

    @Test("a last ask dated in the future, after a clock rollback, does not ask")
    func clockRolledBack() {
        let defaults = freshDefaults()
        #expect(policy(defaults, version: "1.0").consumeRequest(isQuiet: true, now: start))
        let next = ReviewRequestPolicy(defaults: defaults, appVersion: "1.1")
        #expect(!next.consumeRequest(isQuiet: true, now: start - 30 * day))
        #expect(defaults.object(forKey: ReviewRequestPolicy.Key.lastAskedDate) as? Date == start)
    }

    @Test("a new version with fewer than five launches does not ask")
    func newVersionUnderLaunchThreshold() {
        let defaults = freshDefaults()
        let p = policy(defaults, version: "2.0", launches: 4)
        #expect(!p.consumeRequest(isQuiet: true, now: start))
        p.noteLaunch()
        #expect(p.consumeRequest(isQuiet: true, now: start))
    }

    @Test("asks once per app version, even after 120 days")
    func oncePerVersion() {
        let defaults = freshDefaults()
        let p = policy(defaults)
        #expect(p.consumeRequest(isQuiet: true, now: start))
        #expect(!p.consumeRequest(isQuiet: true, now: start + 1))
        #expect(!p.consumeRequest(isQuiet: true, now: start + 200 * day))
        #expect(defaults.string(forKey: ReviewRequestPolicy.Key.lastAskedVersion) == "1.0")
        #expect(defaults.object(forKey: ReviewRequestPolicy.Key.lastAskedDate) as? Date == start)
    }

    @Test("a new version still waits out the 120 days")
    func throttledFor120Days() {
        let defaults = freshDefaults()
        #expect(policy(defaults, version: "1.0").consumeRequest(isQuiet: true, now: start))
        let next = ReviewRequestPolicy(defaults: defaults, appVersion: "1.1")
        #expect(!next.consumeRequest(isQuiet: true, now: start + 119 * day))
        #expect(defaults.string(forKey: ReviewRequestPolicy.Key.lastAskedVersion) == "1.0")
        #expect(next.consumeRequest(isQuiet: true, now: start + 120 * day))
        #expect(defaults.string(forKey: ReviewRequestPolicy.Key.lastAskedVersion) == "1.1")
        #expect(defaults.object(forKey: ReviewRequestPolicy.Key.lastAskedDate) as? Date == start + 120 * day)
    }
}
