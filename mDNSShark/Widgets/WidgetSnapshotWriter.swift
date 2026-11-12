// mDNSShark/Widgets/WidgetSnapshotWriter.swift
import Combine
import Foundation
import WidgetKit
import WidgetSnapshot
import os

/// Decides whether a finished scan may replace the widget snapshot; a result that only reflects missing Local Network access never does.
enum WidgetSnapshotGuard {
    enum Verdict: Equatable { case write, keepPrevious }

    /// `permission` is this scan's own check (nil while unresolved); `requiresGrant` is set for a scan that ended with the app not active.
    static func verdict(deviceCount: Int, permission: LocalNetworkPermissionGate.Decision?, deniedBanner: Bool,
                        requiresGrant: Bool, hasPrevious: Bool) -> Verdict {
        if permission == .denied { return .keepPrevious }
        if deniedBanner, permission != .granted { return .keepPrevious }
        if requiresGrant, permission != .granted { return .keepPrevious }
        if deviceCount == 0, hasPrevious { return .keepPrevious }
        return .write
    }
}

/// What a snapshot write does with the Bluetooth summary: keep the previous one, drop it, or store a new one.
enum BluetoothSnapshotUpdate: Equatable {
    case keep
    case clear
    case set(BluetoothSummary)
}

/// Writes the App Group snapshot the widgets read, once per finished scan and again (debounced) when late enrichment lands.
@MainActor
final class WidgetSnapshotWriter {
    struct Input {
        var devices: [DiscoveredDevice]
        var status: (DiscoveredDevice) -> SecurityStatus
        var ownAddressKeys: Set<String>
        var subnet: String?
        var localNetwork: LocalNetworkPermissionGate.Decision? = nil
        var localNetworkDeniedBanner = false
        var requiresConfirmedGrant = false
        var bluetooth: BluetoothSnapshotUpdate = .keep
    }

    private let store: SnapshotStore?
    private let reload: (String) -> Void
    private let debounce: Duration
    private let now: () -> Date
    private let flagDefaults: UserDefaults
    private var rewriteTask: Task<Void, Never>?
    private let logger = Logger(subsystem: "com.mDNSShark", category: "WidgetSnapshotWriter")

    init(store: SnapshotStore?,
         reload: @escaping (String) -> Void = { WidgetCenter.shared.reloadTimelines(ofKind: $0) },
         debounce: Duration = .seconds(5),
         now: @escaping () -> Date = Date.init,
         flagDefaults: UserDefaults = SharedSettings.suite) {
        self.store = store
        self.reload = reload
        self.debounce = debounce
        self.now = now
        self.flagDefaults = flagDefaults
    }

    /// Appends a history sample for the scan that just ended, then writes and reloads every scan widget.
    /// A scan the guard rejects leaves the old snapshot to age into stale and only clears the widget spinner.
    func scanDidFinish(_ input: Input) {
        rewriteTask?.cancel()
        rewriteTask = nil
        guard let store else { return }
        guard Self.verdict(input, store: store) == .write else {
            logger.notice("Widget snapshot kept: scan ended without confirmed Local Network access or with no devices")
            ScanRequestFlag.clearRunning(in: flagDefaults)
            for kind in WidgetKind.scanKinds { reload(kind) }
            return
        }
        write(input, newScan: true)
    }

    /// Drops the devices and findings seeds and merges later changes; `bluetooth` is already seedless, so it passes through.
    static func rewriteTriggers<D: Publisher, F: Publisher, B: Publisher>(devices: D, findings: F, bluetooth: B) -> AnyPublisher<Void, Never>
    where D.Failure == Never, F.Failure == Never, B.Failure == Never {
        Publishers.Merge3(devices.dropFirst().map { _ in () }, findings.dropFirst().map { _ in () },
                          bluetooth.map { _ in () }).eraseToAnyPublisher()
    }

    /// Debounced; the closure is read after the delay and the write replaces the newest sample instead of adding one.
    func scheduleRewrite(_ input: @escaping @MainActor () -> Input?) {
        rewriteTask?.cancel()
        let delay = debounce
        rewriteTask = Task { [weak self] in
            try? await Task.sleep(for: delay)
            guard !Task.isCancelled, let self else { return }
            guard let store = self.store, case .loaded = store.loadSnapshot(), let value = input(),
                  Self.verdict(value, store: store) == .write else { return }
            self.write(value, newScan: false)
        }
    }

    private static func verdict(_ input: Input, store: SnapshotStore) -> WidgetSnapshotGuard.Verdict {
        var hasPrevious = false
        if case .loaded = store.loadSnapshot() { hasPrevious = true }
        return WidgetSnapshotGuard.verdict(deviceCount: input.devices.count, permission: input.localNetwork,
                                           deniedBanner: input.localNetworkDeniedBanner,
                                           requiresGrant: input.requiresConfirmedGrant, hasPrevious: hasPrevious)
    }

    private func write(_ input: Input, newScan: Bool) {
        guard let store else { return }
        var previous: WidgetSnapshot?
        if case .loaded(let snapshot) = store.loadSnapshot() { previous = snapshot }
        let seen = store.loadSeen()
        let result = Self.makeSnapshot(input: input, previous: previous, seen: seen, now: now(), newScan: newScan)
        // Compared after trimming, the form the file holds, so an unchanged rewrite neither saves nor reloads.
        let unchanged = previous == result.snapshot.trimmedToFit()
        do {
            if result.seen != seen { try store.saveSeen(result.seen) }
            if unchanged { return }
            try store.save(result.snapshot)
        } catch {
            logger.error("Widget snapshot write failed: \(error.localizedDescription, privacy: .public)")
            return
        }
        for kind in WidgetKind.scanKinds { reload(kind) }
    }

    static func makeSnapshot(input: Input, previous: WidgetSnapshot?, seen: [String: Date], now: Date,
                             newScan: Bool) -> (snapshot: WidgetSnapshot, seen: [String: Date]) {
        let devices = input.devices
        var counts = StatusCounts(total: devices.count, secure: 0, warning: 0, critical: 0, pending: 0)
        var typeCounts: [String: Int] = [:]
        var briefs: [DeviceBrief] = []
        let keys = devices.map { DeviceBrief.key(mac: $0.macAddress, ip: $0.ipAddress) }
        let updatedSeen = SeenMap.updated(seen, present: keys, now: now)

        for (device, key) in zip(devices, keys) {
            let status = input.status(device)
            switch status {
            case .secure: counts.secure += 1
            case .warning: counts.warning += 1
            case .critical: counts.critical += 1
            case .pending: counts.pending += 1
            }
            typeCounts[device.deviceType.label, default: 0] += 1
            briefs.append(DeviceBrief(key: key, name: device.hostname, ip: device.ipAddress, typeLabel: device.deviceType.label,
                                      symbol: device.deviceIcon, status: status.accessibilityName,
                                      offNetwork: device.isOnLocalSubnet == false, isGateway: device.isGateway,
                                      firstSeen: updatedSeen[key] ?? now))
        }

        let newDevices = briefs.filter { Staleness.isNew(firstSeen: $0.firstSeen, now: now) }
            .sorted { ($1.firstSeen, $0.key) < ($0.firstSeen, $1.key) }
            .prefix(WidgetSnapshot.newDevicesLimit)

        let hubIndex = devices.firstIndex { $0.isGateway } ?? devices.firstIndex { $0.isOnLocalSubnet != false }
        var ordered: [DeviceBrief] = []
        if let hubIndex { ordered.append(briefs[hubIndex]) }
        let rest = briefs.indices.filter { $0 != hubIndex }
        ordered += rest.filter { !briefs[$0].offNetwork }.map { briefs[$0] }
        ordered += rest.filter { briefs[$0].offNetwork }.map { briefs[$0] }
        let topology = Array(ordered.prefix(WidgetSnapshot.topologyLimit))

        var ownKey: String?
        for (device, key) in zip(devices, keys) {
            let match = ([device.ipAddress] + device.addresses).map(LocalInterfaces.addressMatchKey)
            if !input.ownAddressKeys.isDisjoint(with: match) { ownKey = key; break }
        }

        var history = previous?.history ?? []
        if newScan || history.isEmpty {
            history = WidgetSnapshot.appending(ScanSample(at: now, counts: counts), to: history)
        } else {
            history[history.count - 1].counts = counts
        }

        let bluetooth: BluetoothSummary?
        switch input.bluetooth {
        case .keep: bluetooth = previous?.bluetooth
        case .clear: bluetooth = nil
        case .set(let summary): bluetooth = summary
        }

        let snapshot = WidgetSnapshot(version: WidgetSnapshot.schemaVersion,
                                      scannedAt: newScan ? now : (previous?.scannedAt ?? now),
                                      subnet: input.subnet, counts: counts, typeCounts: typeCounts, history: history,
                                      newDevices: Array(newDevices), topology: topology,
                                      topologyOverflow: max(0, ordered.count - WidgetSnapshot.topologyLimit),
                                      ownDeviceKey: ownKey, bluetooth: bluetooth)
        return (snapshot, updatedSeen)
    }
}
