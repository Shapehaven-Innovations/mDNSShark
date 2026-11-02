import Testing
import Foundation
import Combine
import WidgetSnapshot
@testable import mDNSShark

@Suite("Widget scan decision")
struct WidgetScanDecisionTests {
    let limits = WidgetScanLimits.standard

    @Test("an unsettled permission always falls back to opening the app") func unsettled() {
        for active in [false, true] {
            for running in [false, true] {
                #expect(WidgetScanDecision.plan(permissionSettled: false, appActive: active, scanRunning: running, budget: 25) == .fallbackOpenApp)
            }
        }
    }
    @Test("a scan already running is joined, not restarted") func joins() {
        #expect(WidgetScanDecision.plan(permissionSettled: true, appActive: false, scanRunning: true, budget: 25) == .joinRunningScan)
        #expect(WidgetScanDecision.plan(permissionSettled: true, appActive: true, scanRunning: true, budget: 2) == .joinRunningScan)
    }
    @Test("a background run shortens the scan to fit the budget") func backgroundFits() {
        #expect(WidgetScanDecision.plan(permissionSettled: true, appActive: false, scanRunning: false, budget: 25)
                == .runHeadless(duration: 25 - limits.settleMargin))
        #expect(WidgetScanDecision.plan(permissionSettled: true, appActive: false, scanRunning: false, budget: 60)
                == .runHeadless(duration: limits.standardScan))
    }
    @Test("a background budget too short for a useful scan falls back") func backgroundTooShort() {
        #expect(WidgetScanDecision.plan(permissionSettled: true, appActive: false, scanRunning: false,
                                        budget: limits.minimumScan + limits.settleMargin - 0.1) == .fallbackOpenApp)
        #expect(WidgetScanDecision.plan(permissionSettled: true, appActive: false, scanRunning: false,
                                        budget: limits.minimumScan + limits.settleMargin) == .runHeadless(duration: limits.minimumScan))
    }
    @Test("a foreground app runs the standard scan whatever the budget") func foregroundFullScan() {
        #expect(WidgetScanDecision.plan(permissionSettled: true, appActive: true, scanRunning: false, budget: 1)
                == .runHeadless(duration: limits.standardScan))
    }
    @Test("the budget counts from the intent's start when the process is old or unknown") func budgetWarm() {
        let start = Date(timeIntervalSince1970: 10_000)
        #expect(WidgetScanDecision.budget(intentStart: start, processStart: nil) == limits.total)
        #expect(WidgetScanDecision.budget(intentStart: start, processStart: start.addingTimeInterval(-3600)) == limits.total)
        #expect(WidgetScanDecision.budget(intentStart: start, processStart: start.addingTimeInterval(-limits.total)) == limits.total)
        // A start time after the intent's (clock change) is not trusted.
        #expect(WidgetScanDecision.budget(intentStart: start, processStart: start.addingTimeInterval(5)) == limits.total)
    }
    @Test("a cold launch's startup time comes off the budget") func budgetCold() {
        let start = Date(timeIntervalSince1970: 10_000)
        #expect(WidgetScanDecision.budget(intentStart: start, processStart: start.addingTimeInterval(-3)) == limits.total - 3)
        #expect(WidgetScanDecision.budget(intentStart: start, processStart: start.addingTimeInterval(-0.5)) == limits.total - 0.5)
        #expect(WidgetScanDecision.budget(intentStart: start, processStart: start) == limits.total)
        // Startup that already used most of the budget leaves too little for a scan, so plan falls back.
        let late = WidgetScanDecision.budget(intentStart: start, processStart: start.addingTimeInterval(-20))
        #expect(late == limits.total - 20)
        #expect(WidgetScanDecision.plan(permissionSettled: true, appActive: false, scanRunning: false, budget: late) == .fallbackOpenApp)
    }
    @Test("the process start time reads as a moment in the past") func processStartReads() {
        let date = ProcessStartTime.read()
        #expect(date != nil)
        if let date { #expect(date <= Date()) }
    }
    @Test("the background permission check runs only for a past grant, unsettled gate and inactive app") func preflight() {
        #expect(WidgetScanDecision.shouldPreflight(gateSettled: false, grantedBefore: true, appActive: false))
        #expect(!WidgetScanDecision.shouldPreflight(gateSettled: true, grantedBefore: true, appActive: false))
        #expect(!WidgetScanDecision.shouldPreflight(gateSettled: false, grantedBefore: false, appActive: false))
        #expect(!WidgetScanDecision.shouldPreflight(gateSettled: false, grantedBefore: true, appActive: true))
    }
}

@MainActor
@Suite("Widget scan runner")
struct WidgetScanRunnerTests {
    @MainActor
    final class Fake {
        var gateSettled = true
        var grantedBefore = true
        var appActive = false
        var isScanning = false
        var preflightResult: LocalNetworkPermissionGate.Decision = .granted
        var preflights = 0
        var settles = 0
        var restarts: [TimeInterval] = []
        var finishOnRestart = true
        var reloads = 0
        let finished = PassthroughSubject<Void, Never>()
        let defaults = UserDefaults(suiteName: "WidgetScanRunnerTests.\(UUID().uuidString)")!
        let now = Date(timeIntervalSince1970: 50_000)
        var processStart: Date?
        let tasks = FakeBackgroundTasks()
    }

    @MainActor
    final class FakeBackgroundTasks: BackgroundTaskAsserting {
        var grants = true
        var begun = 0
        var ended: [BackgroundTaskToken] = []
        var expiration: (@MainActor () -> Void)?

        func begin(expiration: @escaping @MainActor () -> Void) -> BackgroundTaskToken? {
            begun += 1
            self.expiration = expiration
            return grants ? BackgroundTaskToken(rawValue: begun) : nil
        }
        func end(_ token: BackgroundTaskToken) { ended.append(token) }
    }

    /// Short tail so tests can watch the assertion outlive run().
    static let shortTail = WidgetScanLimits(total: 25, minimumScan: 10, preflightTimeout: 4, settleMargin: 1.5, standardScan: 25, tailGrace: 0.2)

    func runner(_ fake: Fake, limits: WidgetScanLimits = .standard) -> WidgetScanRunner {
        WidgetScanRunner(limits: limits, environment: WidgetScanRunner.Environment(
            gateSettled: { fake.gateSettled },
            grantedBefore: { fake.grantedBefore },
            appActive: { fake.appActive },
            isScanning: { fake.isScanning },
            preflight: { _ in fake.preflights += 1; return fake.preflightResult },
            settleGate: { fake.settles += 1; fake.gateSettled = true },
            restartScan: { duration in
                fake.restarts.append(duration)
                if fake.finishOnRestart { fake.finished.send() }
            },
            scanFinished: fake.finished.eraseToAnyPublisher(),
            defaults: fake.defaults,
            reloadWidgets: { fake.reloads += 1 },
            now: { fake.now },
            processStart: fake.processStart,
            backgroundTasks: fake.tasks))
    }

    @Test("a settled background run scans once and leaves no flag") func headless() async {
        let fake = Fake()
        let outcome = await runner(fake).run(openApp: { Issue.record("must not open the app"); return true })
        #expect(outcome == .scanned)
        #expect(fake.restarts == [25 - WidgetScanLimits.standard.settleMargin])
        #expect(fake.defaults.object(forKey: ScanRequestFlag.key) == nil)
        #expect(fake.defaults.object(forKey: ScanRequestFlag.lastRequestKey) as? Date == fake.now)
        #expect(fake.reloads >= 1)
        #expect(fake.preflights == 0)
    }
    @Test("a cold launch after a past grant checks permission, settles the gate and scans") func coldGranted() async {
        let fake = Fake(); fake.gateSettled = false
        let outcome = await runner(fake).run(openApp: { Issue.record("must not open the app"); return true })
        #expect(outcome == .scanned)
        #expect(fake.preflights == 1 && fake.settles == 1 && fake.restarts.count == 1)
    }
    @Test("a cold launch whose check is not granted opens the app with the old flag") func coldDenied() async {
        for result: LocalNetworkPermissionGate.Decision in [.denied, .undetermined] {
            let fake = Fake(); fake.gateSettled = false; fake.preflightResult = result
            var opened = 0
            let outcome = await runner(fake).run(openApp: { opened += 1; return true })
            #expect(outcome == .openedApp)
            #expect(opened == 1 && fake.settles == 0 && fake.restarts.isEmpty)
            #expect(ScanRequestFlag.consume(from: fake.defaults, now: fake.now))
        }
    }
    @Test("never granted before: no network check at all, straight to the app") func neverGranted() async {
        let fake = Fake(); fake.gateSettled = false; fake.grantedBefore = false
        var opened = 0
        let outcome = await runner(fake).run(openApp: { opened += 1; return true })
        #expect(outcome == .openedApp && opened == 1 && fake.preflights == 0 && fake.restarts.isEmpty)
    }
    @Test("an active app with an unsettled gate only stamps the flag for the scene to consume") func activeUnsettled() async {
        let fake = Fake(); fake.gateSettled = false; fake.appActive = true
        let outcome = await runner(fake).run(openApp: { Issue.record("already foreground"); return true })
        #expect(outcome == .handedToApp && fake.preflights == 0 && fake.restarts.isEmpty)
        #expect(ScanRequestFlag.consume(from: fake.defaults, now: fake.now))
    }
    @Test("when the app cannot be opened the spinner is cleared and the flag kept") func cannotOpen() async {
        let fake = Fake(); fake.gateSettled = false; fake.grantedBefore = false
        let outcome = await runner(fake).run(openApp: { false })
        #expect(outcome == .leftFlag)
        #expect(ScanRequestFlag.awaitingUntil(in: fake.defaults, scannedAt: nil, now: fake.now) == nil)
        #expect(ScanRequestFlag.consume(from: fake.defaults, now: fake.now))
    }
    @Test("a running scan is joined without a restart") func join() async {
        let fake = Fake(); fake.isScanning = true
        let finished = fake.finished
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(50))
            finished.send()
        }
        let outcome = await runner(fake).run(openApp: { false })
        #expect(outcome == .joined && fake.restarts.isEmpty)
    }
    @Test("a scan that outlasts the budget returns timed out") func timeout() async {
        let fake = Fake(); fake.finishOnRestart = false
        let limits = WidgetScanLimits(total: 0.3, minimumScan: 0.1, preflightTimeout: 0.1, settleMargin: 0.05, standardScan: 25)
        let outcome = await runner(fake, limits: limits).run(openApp: { false })
        #expect(outcome == .timedOut && fake.restarts.count == 1)
    }

    @Test("a cold background launch shortens the scan by the startup time") func coldBudget() async {
        let fake = Fake(); fake.processStart = fake.now.addingTimeInterval(-3)
        let outcome = await runner(fake).run(openApp: { Issue.record("must not open the app"); return true })
        #expect(outcome == .scanned)
        #expect(fake.restarts == [25 - 3 - WidgetScanLimits.standard.settleMargin])
    }
    @Test("a foreground widget run keeps the standard scan even right after launch") func foregroundIgnoresStartup() async {
        let fake = Fake(); fake.appActive = true; fake.processStart = fake.now.addingTimeInterval(-3)
        _ = await runner(fake).run(openApp: { false })
        #expect(fake.restarts == [WidgetScanLimits.standard.standardScan])
    }
    @Test("a scanned run holds a background task past its return, then ends it") func tailHeld() async throws {
        let fake = Fake()
        let outcome = await runner(fake, limits: Self.shortTail).run(openApp: { false })
        #expect(outcome == .scanned)
        #expect(fake.tasks.begun == 1)
        #expect(fake.tasks.ended.isEmpty)
        try await Task.sleep(for: .milliseconds(600))
        #expect(fake.tasks.ended == [BackgroundTaskToken(rawValue: 1)])
    }
    @Test("a run that hands off to the app ends its background task at once") func tailEndsOnFallback() async {
        let fake = Fake(); fake.gateSettled = false; fake.grantedBefore = false
        let outcome = await runner(fake, limits: Self.shortTail).run(openApp: { true })
        #expect(outcome == .openedApp)
        #expect(fake.tasks.ended == [BackgroundTaskToken(rawValue: 1)])

        let left = Fake(); left.gateSettled = false; left.grantedBefore = false
        #expect(await runner(left, limits: Self.shortTail).run(openApp: { false }) == .leftFlag)
        #expect(left.tasks.ended == [BackgroundTaskToken(rawValue: 1)])
    }
    @Test("a timed-out run keeps its background task until the scan finishes") func tailWaitsForScan() async throws {
        let fake = Fake(); fake.finishOnRestart = false
        let limits = WidgetScanLimits(total: 0.3, minimumScan: 0.1, preflightTimeout: 0.1, settleMargin: 0.05, standardScan: 25, tailGrace: 0.05)
        #expect(await runner(fake, limits: limits).run(openApp: { false }) == .timedOut)
        try await Task.sleep(for: .milliseconds(300))
        #expect(fake.tasks.ended.isEmpty)
        fake.finished.send()
        try await Task.sleep(for: .milliseconds(400))
        #expect(fake.tasks.ended.count == 1)
    }
    @Test("the background task's expiration clears the spinner and ends the task") func expirationClears() async throws {
        let fake = Fake(); fake.finishOnRestart = false
        let limits = WidgetScanLimits(total: 0.3, minimumScan: 0.1, preflightTimeout: 0.1, settleMargin: 0.05, standardScan: 25, tailGrace: 0.05)
        #expect(await runner(fake, limits: limits).run(openApp: { false }) == .timedOut)
        #expect(ScanRequestFlag.awaitingUntil(in: fake.defaults, scannedAt: nil, now: fake.now) != nil)
        let reloadsBefore = fake.reloads
        fake.tasks.expiration?()
        #expect(ScanRequestFlag.awaitingUntil(in: fake.defaults, scannedAt: nil, now: fake.now) == nil)
        #expect(fake.reloads == reloadsBefore + 1)
        #expect(fake.tasks.ended.count == 1)
        // A scan end after expiration must not end the task twice.
        fake.finished.send()
        try await Task.sleep(for: .milliseconds(200))
        #expect(fake.tasks.ended.count == 1)
    }
    @Test("a refused background task does not stop the scan") func taskRefused() async {
        let fake = Fake(); fake.tasks.grants = false
        #expect(await runner(fake, limits: Self.shortTail).run(openApp: { false }) == .scanned)
        #expect(fake.tasks.ended.isEmpty)
    }
}
