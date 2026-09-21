// mDNSShark/App/LocalNetworkPermissionGate.swift
import Foundation
import Network
import os

/// Waits for iOS's Local Network Privacy decision to resolve before the
/// app's very first automatic scan fires.
///
/// Apple gives no API to directly query this permission's state — the
/// system alert only appears in response to real local-network traffic,
/// and any local-network operation that races ahead of the user's answer
/// gets an instant, non-retried denial (`EHOSTUNREACH` on a raw BSD
/// socket, `NWPathKey=unsatisfied (Local network prohibited)` on
/// NWConnection/URLSession) rather than being queued — so a probe caught
/// in that window fails for good, not just until the user taps Allow.
///
/// Found via a live device bug: `AppCoordinator.init()` used to fire the
/// real scan immediately on launch, which is structurally guaranteed to
/// lose this race on a fresh install — the permission alert can't be
/// answered before the scan's own traffic is what causes it to render in
/// the first place.
///
/// Uses the documented Bonjour preflight technique (an `NWListener`
/// advertising a dedicated, unused-elsewhere service type, browsed for by
/// an `NWBrowser` on the same device): finding our own advertised service
/// means the decision resolved as granted; the browser reporting DNS-SD's
/// `kDNSServiceErr_PolicyDenied` via `.waiting`, confirmed still true after
/// a short debounce, means it resolved as denied. A raw multicast
/// `NWConnection` canary was tried first and rejected — it's gated behind
/// `com.apple.developer.networking.multicast` (currently unapproved, see
/// todo.md), so it would never reach `.ready` and would always hit the
/// timeout below, defeating the point. Bonjour APIs need no such
/// entitlement.
enum LocalNetworkPermissionGate {
    private static let logger = Logger(subsystem: "com.mDNSShark", category: "LocalNetworkPermissionGate")

    /// A service type used only by this preflight check — never advertised
    /// or browsed anywhere else in the app. Must be listed in
    /// `NSBonjourServices` in Info.plist. `NetworkScanner.processBrowseResults`
    /// also explicitly excludes this type so it can never surface as a fake
    /// discovered device if a manual scan runs while this is still resolving.
    private static let serviceType = "_mdnssharklnp._tcp"

    /// How long a `PolicyDenied` sighting must persist before treating it
    /// as a final "denied" answer. `kDNSServiceErr_PolicyDenied` is
    /// Apple-documented as the signal for a denied decision, but nothing
    /// rules out it also appearing transiently while the alert is still
    /// pending/unanswered — resolving on the very first sighting would
    /// reproduce the exact race this file exists to prevent, just via the
    /// denied path instead of no gate at all. Re-checking `newBrowser.state`
    /// after this delay confirms it's a real, settled denial rather than a
    /// momentary blip.
    private static let deniedDebounceInterval: TimeInterval = 1.5

    /// Resolves once the OS has settled its Local Network Privacy decision
    /// (granted or denied), or after `timeout` elapses so a user who
    /// ignores/dismisses the alert never blocks the scanner forever.
    ///
    /// Call once, at launch, before the automatic first scan. Not meant to
    /// gate the manual "Scan" button — by the time a user can tap that,
    /// the app is already visible and this has already had its chance to
    /// resolve.
    static func waitForDecision(timeout: TimeInterval = 30) async {
        await withCheckedContinuation { continuation in
            var resumed = false
            var listener: NWListener?
            var browser: NWBrowser?
            var timeoutWorkItem: DispatchWorkItem?

            let cleanup: () -> Void = {
                listener?.cancel()
                browser?.cancel()
                timeoutWorkItem?.cancel()
            }

            let resumeOnce: (String) -> Void = { reason in
                guard !resumed else { return }
                resumed = true
                logger.debug("LocalNetworkPermissionGate: resolved (\(reason, privacy: .public))")
                cleanup()
                continuation.resume()
            }

            let newListener: NWListener
            do {
                newListener = try NWListener(using: .tcp)
            } catch {
                // Can't even set up the local check — fail open immediately
                // rather than block a real scan on a broken preflight.
                logger.error("LocalNetworkPermissionGate: NWListener setup failed: \(error.localizedDescription, privacy: .public)")
                resumeOnce("listener-setup-failed")
                return
            }
            newListener.service = NWListener.Service(name: UUID().uuidString, type: serviceType)
            newListener.newConnectionHandler = { $0.cancel() }  // never actually connected to
            newListener.stateUpdateHandler = { state in
                if case .failed(let error) = state {
                    // Without a working listener, "granted" can only ever
                    // be detected by the browser finding it — with no
                    // listener, that path is dead, so this would otherwise
                    // silently sit until the full timeout on every launch,
                    // even on an already-granted device. Fail open instead.
                    logger.error("LocalNetworkPermissionGate: NWListener failed post-start: \(error.localizedDescription, privacy: .public)")
                    resumeOnce("listener-failed-poststart")
                }
            }
            newListener.start(queue: .main)
            listener = newListener

            let newBrowser = NWBrowser(for: .bonjour(type: serviceType, domain: nil), using: .tcp)
            newBrowser.browseResultsChangedHandler = { results, _ in
                // Finding our own just-advertised listener is only possible
                // if local-network browsing is actually permitted.
                if !results.isEmpty { resumeOnce("granted") }
            }
            newBrowser.stateUpdateHandler = { state in
                if case .waiting(let error) = state,
                   case .dns(let dnsError) = error,
                   dnsError == kDNSServiceErr_PolicyDenied {
                    DispatchQueue.main.asyncAfter(deadline: .now() + deniedDebounceInterval) {
                        guard !resumed else { return }
                        if case .waiting(let stillError) = newBrowser.state,
                           case .dns(let stillDnsError) = stillError,
                           stillDnsError == kDNSServiceErr_PolicyDenied {
                            resumeOnce("denied")
                        }
                        // Otherwise the state moved on (granted, or still
                        // genuinely undetermined) — let the normal handlers
                        // or the timeout resolve it instead.
                    }
                }
                // Any other `.waiting` just means the decision is still
                // undetermined (or a transient, unrelated condition) —
                // keep waiting rather than treating it as final.
            }
            newBrowser.start(queue: .main)
            browser = newBrowser

            let work = DispatchWorkItem { resumeOnce("timeout") }
            timeoutWorkItem = work
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout, execute: work)
        }
    }
}
