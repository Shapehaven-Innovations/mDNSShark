// mDNSSharkTests/LocalNetworkPermissionGateTests.swift
import Testing
import Network
@testable import mDNSShark

@Suite("LocalNetworkPermissionGate decision mapping")
struct LocalNetworkPermissionGateTests {

    @Test("waiting on kDNSServiceErr_PolicyDenied is the denied signal")
    func policyDeniedWaiting() {
        let state = NWBrowser.State.waiting(.dns(DNSServiceErrorType(kDNSServiceErr_PolicyDenied)))
        #expect(LocalNetworkPermissionGate.isPolicyDenied(state))
    }

    @Test("waiting on any other DNS or POSIX error is not a denial")
    func otherWaitingErrors() {
        #expect(!LocalNetworkPermissionGate.isPolicyDenied(.waiting(.dns(DNSServiceErrorType(kDNSServiceErr_NoSuchName)))))
        #expect(!LocalNetworkPermissionGate.isPolicyDenied(.waiting(.posix(.ENETDOWN))))
    }

    @Test("setup, ready and cancelled are never a denial")
    func nonWaitingStates() {
        #expect(!LocalNetworkPermissionGate.isPolicyDenied(.setup))
        #expect(!LocalNetworkPermissionGate.isPolicyDenied(.ready))
        #expect(!LocalNetworkPermissionGate.isPolicyDenied(.cancelled))
    }

    @Test("denied shows the banner, granted hides it")
    func settledDecisions() {
        #expect(LocalNetworkPermissionGate.Decision.denied.showsDeniedBanner(current: false))
        #expect(LocalNetworkPermissionGate.Decision.denied.showsDeniedBanner(current: true))
        #expect(!LocalNetworkPermissionGate.Decision.granted.showsDeniedBanner(current: false))
        #expect(!LocalNetworkPermissionGate.Decision.granted.showsDeniedBanner(current: true))
    }

    @Test("undetermined keeps whatever the banner was showing")
    func undeterminedKeepsCurrent() {
        #expect(!LocalNetworkPermissionGate.Decision.undetermined.showsDeniedBanner(current: false))
        #expect(LocalNetworkPermissionGate.Decision.undetermined.showsDeniedBanner(current: true))
    }
}
