// mDNSShark/Widgets/WidgetScanRunner.swift
import Foundation
import Combine
import UIKit
import WidgetKit
import WidgetSnapshot

/// What a widget Scan tap does once it reaches the app process.
enum WidgetScanPlan: Equatable {
    case runHeadless(duration: TimeInterval)
    case joinRunningScan
    case fallbackOpenApp
}

/// Time limits for a widget-triggered scan; iOS gives a background intent about 30 s, so the total stays under that.
struct WidgetScanLimits: Equatable {
    var total: TimeInterval
    var minimumScan: TimeInterval
    var preflightTimeout: TimeInterval
    var settleMargin: TimeInterval
    var standardScan: TimeInterval
    /// How long the background task outlives perform(), long enough for the writer's 5 s debounced rewrite.
    var tailGrace: TimeInterval = 6

    static let standard = WidgetScanLimits(total: 25, minimumScan: 10, preflightTimeout: 4, settleMargin: 1.5, standardScan: 25)
}

enum WidgetScanDecision {
    /// Seconds this run may use from the intent's start; on a cold launch the time since process start is taken off, so the whole run stays near `total` from launch.
    static func budget(intentStart: Date, processStart: Date?, limits: WidgetScanLimits = .standard) -> TimeInterval {
        guard let processStart else { return limits.total }
        let launchElapsed = intentStart.timeIntervalSince(processStart)
        guard launchElapsed > 0, launchElapsed < limits.total else { return limits.total }
        return limits.total - launchElapsed
    }

    /// Only a past grant justifies a Local Network check in the background, where iOS denies an undetermined app silently (TN3179).
    static func shouldPreflight(gateSettled: Bool, grantedBefore: Bool, appActive: Bool) -> Bool {
        !gateSettled && grantedBefore && !appActive
    }

    /// An unsettled permission always takes the old open-the-app path; a foreground app is not time limited, a background one is.
    static func plan(permissionSettled: Bool, appActive: Bool, scanRunning: Bool, budget: TimeInterval,
                     limits: WidgetScanLimits = .standard) -> WidgetScanPlan {
        guard permissionSettled else { return .fallbackOpenApp }
        if scanRunning { return .joinRunningScan }
        if appActive { return .runHeadless(duration: limits.standardScan) }
        let duration = min(limits.standardScan, budget - limits.settleMargin)
        return duration >= limits.minimumScan ? .runHeadless(duration: duration) : .fallbackOpenApp
    }
}

/// Runs a widget Scan request inside the app process with no UI, then returns once the snapshot is written or the budget ends.
@MainActor
final class WidgetScanRunner {
    enum Outcome: Equatable {
        case scanned, joined, timedOut, handedToApp, openedApp, leftFlag
    }

    struct Environment {
        var gateSettled: () -> Bool
        var grantedBefore: () -> Bool
        var appActive: () -> Bool
        var isScanning: () -> Bool
        var preflight: (TimeInterval) async -> LocalNetworkPermissionGate.Decision
        var settleGate: () -> Void
        var restartScan: (TimeInterval) -> Void
        var scanFinished: AnyPublisher<Void, Never>
        var defaults: UserDefaults
        var reloadWidgets: () -> Void
        var now: () -> Date
        var processStart: Date?
        var backgroundTasks: (any BackgroundTaskAsserting)?
    }

    private let limits: WidgetScanLimits
    private let env: Environment

    init(limits: WidgetScanLimits = .standard, environment: Environment) {
        self.limits = limits
        self.env = environment
    }

    /// Holds a background task from start until the post-return work (late snapshot write, reload, spinner clear) is done.
    func run(openApp: @MainActor () async -> Bool) async -> Outcome {
        let tail = TailAssertion(tasks: env.backgroundTasks)
        let defaults = env.defaults, reload = env.reloadWidgets
        tail.begin(onExpire: {
            ScanRequestFlag.clearRunning(in: defaults)
            reload()
        })
        let outcome = await runScan(openApp: openApp)
        switch outcome {
        case .scanned, .joined:
            tail.end(after: limits.tailGrace)
        case .timedOut:
            tail.end(afterNext: env.scanFinished, grace: limits.tailGrace)
        case .handedToApp, .openedApp, .leftFlag:
            tail.end()
        }
        return outcome
    }

    private func runScan(openApp: @MainActor () async -> Bool) async -> Outcome {
        let start = env.now()
        let deadline = start.addingTimeInterval(WidgetScanDecision.budget(intentStart: start, processStart: env.processStart, limits: limits))
        ScanRequestFlag.markRunning(in: env.defaults, at: start)
        env.reloadWidgets()

        let active = env.appActive()
        var settled = env.gateSettled()
        if WidgetScanDecision.shouldPreflight(gateSettled: settled, grantedBefore: env.grantedBefore(), appActive: active),
           await env.preflight(limits.preflightTimeout) == .granted {
            env.settleGate()
            settled = true
        }

        let plan = WidgetScanDecision.plan(permissionSettled: settled, appActive: active, scanRunning: env.isScanning(),
                                           budget: deadline.timeIntervalSince(env.now()), limits: limits)
        switch plan {
        case .fallbackOpenApp:
            // The same flag ScanNowIntent leaves, consumed by ContentView once the splash and launch gate allow it.
            ScanRequestFlag.stamp(in: env.defaults, at: env.now())
            if active { return .handedToApp }
            if await openApp() { return .openedApp }
            ScanRequestFlag.clearRunning(in: env.defaults)
            env.reloadWidgets()
            return .leftFlag
        case .joinRunningScan:
            return await awaitScanEnd(until: deadline, starting: {}) ? .joined : .timedOut
        case .runHeadless(let duration):
            let restart = env.restartScan
            return await awaitScanEnd(until: deadline, starting: { restart(duration) }) ? .scanned : .timedOut
        }
    }

    /// Subscribes before `start` so a scan that ends at once is not missed; scanFinished's other sinks (the snapshot writer) have run by the time this resumes.
    private func awaitScanEnd(until deadline: Date, starting start: () -> Void) async -> Bool {
        let waiter = ScanEndWaiter()
        let delay = max(0, deadline.timeIntervalSince(env.now()))
        let finished = env.scanFinished
        return await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
            waiter.continuation = continuation
            waiter.cancellable = finished.first().sink { _ in waiter.finish(true) }
            start()
            waiter.timer = Task { @MainActor in
                try? await Task.sleep(for: .seconds(delay))
                waiter.finish(false)
            }
        }
    }
}

struct BackgroundTaskToken: Equatable {
    let rawValue: Int
}

/// The UIApplication background task pair, behind a protocol so the runner's tail can be tested.
@MainActor
protocol BackgroundTaskAsserting: AnyObject {
    /// Nil when the system refuses; `expiration` runs on the main actor if time runs out first.
    func begin(expiration: @escaping @MainActor () -> Void) -> BackgroundTaskToken?
    func end(_ token: BackgroundTaskToken)
}

@MainActor
final class UIApplicationBackgroundTasks: BackgroundTaskAsserting {
    func begin(expiration: @escaping @MainActor () -> Void) -> BackgroundTaskToken? {
        let id = UIApplication.shared.beginBackgroundTask(withName: "WidgetScan") {
            MainActor.assumeIsolated { expiration() }
        }
        return id == .invalid ? nil : BackgroundTaskToken(rawValue: id.rawValue)
    }

    func end(_ token: BackgroundTaskToken) {
        UIApplication.shared.endBackgroundTask(UIBackgroundTaskIdentifier(rawValue: token.rawValue))
    }
}

/// One background task per widget run; ending is idempotent, and expiration runs its handler only while the task is still held.
@MainActor
private final class TailAssertion {
    private let tasks: (any BackgroundTaskAsserting)?
    private var token: BackgroundTaskToken?
    private var cancellable: AnyCancellable?
    private var waiter: Task<Void, Never>?

    init(tasks: (any BackgroundTaskAsserting)?) { self.tasks = tasks }

    func begin(onExpire: @escaping @MainActor () -> Void) {
        token = tasks?.begin { [weak self] in
            guard let self, self.token != nil else { return }
            onExpire()
            self.end()
        }
    }

    func end() {
        cancellable?.cancel()
        cancellable = nil
        waiter?.cancel()
        waiter = nil
        guard let token else { return }
        self.token = nil
        tasks?.end(token)
    }

    func end(after grace: TimeInterval) {
        guard token != nil else { return }
        waiter = Task { @MainActor in
            try? await Task.sleep(for: .seconds(grace))
            guard !Task.isCancelled else { return }
            self.end()
        }
    }

    /// For a scan still running at return: its finish writes the snapshot, then the grace covers the debounced rewrite.
    func end(afterNext finished: AnyPublisher<Void, Never>, grace: TimeInterval) {
        guard token != nil else { return }
        cancellable = finished.first().sink { [self] _ in
            cancellable = nil
            end(after: grace)
        }
    }
}

/// The time this process was started, from the kernel, so a cold launch's startup can be counted against the intent budget.
enum ProcessStartTime {
    static func read() -> Date? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        guard sysctl(&mib, u_int(mib.count), &info, &size, nil, 0) == 0, size > 0 else { return nil }
        let started = info.kp_proc.p_un.__p_starttime
        guard started.tv_sec > 0 else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(started.tv_sec) + TimeInterval(started.tv_usec) / 1_000_000)
    }
}

@MainActor
private final class ScanEndWaiter {
    var continuation: CheckedContinuation<Bool, Never>?
    var cancellable: AnyCancellable?
    var timer: Task<Void, Never>?

    func finish(_ ended: Bool) {
        guard let continuation else { return }
        self.continuation = nil
        cancellable?.cancel()
        timer?.cancel()
        continuation.resume(returning: ended)
    }
}

extension AppCoordinator: WidgetScanPerforming {
    func performWidgetScan(openApp: @escaping @MainActor () async -> Bool) async {
        let vm = networkScanViewModel
        let runner = WidgetScanRunner(environment: WidgetScanRunner.Environment(
            gateSettled: { vm.launchGateSettled },
            grantedBefore: { vm.localNetworkGrantedBefore },
            appActive: { UIApplication.shared.applicationState == .active },
            isScanning: { vm.isScanning },
            preflight: { await LocalNetworkPermissionGate.waitForDecision(timeout: $0) },
            settleGate: { vm.settleLaunchGateAfterBackgroundGrant() },
            restartScan: { vm.restartScan(duration: $0) },
            scanFinished: vm.scanFinished.eraseToAnyPublisher(),
            defaults: SharedSettings.suite,
            reloadWidgets: { for kind in WidgetKind.scanKinds { WidgetCenter.shared.reloadTimelines(ofKind: kind) } },
            now: Date.init,
            processStart: ProcessStartTime.read(),
            backgroundTasks: UIApplicationBackgroundTasks()))
        _ = await runner.run(openApp: openApp)
    }
}
