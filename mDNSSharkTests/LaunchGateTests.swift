// mDNSSharkTests/LaunchGateTests.swift
import Testing
@testable import mDNSShark

@MainActor
@Suite("Launch Local Network gate plan")
struct LaunchGateTests {
    private typealias VM = NetworkScanViewModel

    @Test("granted on a fresh launch settles and runs the first scan")
    func grantedFirstScan() {
        let plan = VM.launchGatePlan(decision: .granted, hasScanned: false, autoScanNeedsRedo: false)
        #expect(plan == .init(settles: true, action: .scan, autoScanNeedsRedo: false))
    }

    @Test("granted after the user already scanned manually settles without a second scan")
    func grantedAfterManualScan() {
        let plan = VM.launchGatePlan(decision: .granted, hasScanned: true, autoScanNeedsRedo: false)
        #expect(plan == .init(settles: true, action: .none, autoScanNeedsRedo: false))
    }

    @Test("undetermined scans once, does not settle, and remembers the scan may have been denied")
    func undeterminedScansAndRemembers() {
        let plan = VM.launchGatePlan(decision: .undetermined, hasScanned: false, autoScanNeedsRedo: false)
        #expect(plan == .init(settles: false, action: .scan, autoScanNeedsRedo: true))
    }

    @Test("denied does not settle, so a later foreground retries and can raise the alert again")
    func deniedDoesNotSettle() {
        let plan = VM.launchGatePlan(decision: .denied, hasScanned: false, autoScanNeedsRedo: false)
        #expect(plan == .init(settles: false, action: .scan, autoScanNeedsRedo: true))
    }

    @Test("granted after a scan that ran before permission restarts it once")
    func grantedAfterLostScanRestarts() {
        let plan = VM.launchGatePlan(decision: .granted, hasScanned: true, autoScanNeedsRedo: true)
        #expect(plan == .init(settles: true, action: .restart, autoScanNeedsRedo: false))
    }

    @Test("a repeat undetermined or denied run never starts a second scan")
    func repeatRunsDoNotRescan() {
        for decision in [LocalNetworkPermissionGate.Decision.undetermined, .denied] {
            let plan = VM.launchGatePlan(decision: decision, hasScanned: true, autoScanNeedsRedo: true)
            #expect(plan == .init(settles: false, action: .none, autoScanNeedsRedo: true))
        }
    }

    @Test("the gate starts only when unsettled, idle and the app is active")
    func startConditions() {
        #expect(VM.shouldStartLaunchGate(settled: false, inFlight: false, isActive: true))
        #expect(!VM.shouldStartLaunchGate(settled: true, inFlight: false, isActive: true))
        #expect(!VM.shouldStartLaunchGate(settled: false, inFlight: true, isActive: true))
        #expect(!VM.shouldStartLaunchGate(settled: false, inFlight: false, isActive: false))
    }

    @Test("a new view model has not started or settled the gate")
    func freshState() {
        let vm = VM()
        #expect(!vm.launchGateSettled)
    }
}
