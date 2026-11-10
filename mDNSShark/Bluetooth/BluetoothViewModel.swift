import Foundation
import Combine
import DeviceFingerprint
import WidgetSnapshot

enum BLEScanEndReason: Equatable {
    case user, timeout, sceneInactive, powerLost
}

/// App-scoped owner of Bluetooth scanning. Bluetooth rows never flow into `DiscoveredDevice`; LAN devices are only read for suggestions.
@MainActor
final class BluetoothViewModel: ObservableObject {
    static let scanDuration: TimeInterval = 25
    static let publishInterval: Duration = .milliseconds(500)
    static let readTimeout: Duration = .seconds(5)
    static let logCapacity = 5000

    /// First seen, then display name, then id, so rows never move under a finger while RSSI changes.
    @Published private(set) var peripherals: [BLEPeripheral] = []
    @Published private(set) var isScanning = false
    @Published private(set) var authorization: BLEAuthorization
    @Published private(set) var powerState: BLEPowerState = .unknown
    @Published private(set) var matches: BLEMatchTable = .empty
    @Published private(set) var suggestedLANDeviceIDs: Set<UUID> = []
    @Published private(set) var lastScanSummary: BluetoothSummary?
    @Published private(set) var saved: [BLESavedDevice] = []
    @Published private(set) var log: [BLEAdvertisementRecord] = []
    private(set) var hasScannedThisSession = false

    /// Rows with a sighting this session whose lifecycle is not `.expired`.
    var nearbyCount: Int { Self.nearbyCount(peripherals: peripherals, now: now()) }

    /// The same rule `DevicesListPlan` uses for which peripherals are listed, so the count matches the rows.
    nonisolated static func nearbyCount(peripherals: [BLEPeripheral], now: Date) -> Int {
        peripherals.filter { $0.lifecycle(now: now) != .expired }.count
    }

    /// Published rows heard during the running scan.
    var seenThisScanCount: Int { peripherals.filter { seenThisScan.contains($0.id) }.count }

    /// Published rows heard during the running scan that carry a suggestion; ties never count.
    var seenThisScanSuggestedCount: Int {
        let suggested = matches.suggestedPeripheralIDs
        return peripherals.filter { seenThisScan.contains($0.id) && suggested.contains($0.id) }.count
    }

    /// True while sightings wait for the next publish tick.
    var hasPendingPublish: Bool { tickTask != nil }

    private let makeCentral: @MainActor () -> any BLECentral
    private let readAuthorization: () -> BLEAuthorization
    private let store: BLEDeviceStore
    private let parser: BLEAdvertisementParser
    private let now: () -> Date
    private let interval: Duration

    private var central: (any BLECentral)?
    private var eventsSubscription: AnyCancellable?
    /// The working set; sightings land here at once and reach `peripherals` on the next tick.
    private var rows = BLEPeripheralSet()
    private var pendingRecords: [BLEAdvertisementRecord] = []
    private var tickTask: Task<Void, Never>?
    private var timeoutTask: Task<Void, Never>?
    /// A scan the user asked for that is still waiting on power, the prompt answer or the scene.
    private var requestedDuration: TimeInterval?
    private var seenThisScan: Set<UUID> = []
    /// The rows counted in `lastScanSummary`, so a matcher re-run can refresh its `suggested`.
    private var summarySeen: Set<UUID> = []
    /// The most recent CoreBluetooth identifier per row, used only for the user-started read.
    private var latestIdentifier: [UUID: UUID] = [:]
    /// Rows folded into another row, so a detail screen opened on the old id follows the device.
    private var foldedInto: [UUID: UUID] = [:]
    /// The identifiers each folded row held, so a later split can drop a redirect that now points at the wrong device.
    private var foldedIdentifiers: [UUID: Set<UUID>] = [:]
    /// When the running scan began; a split-off row counts toward this scan only if it was heard since.
    private var scanStartedAt: Date?
    private var candidates: [BLEMatchCandidate] = []
    private var matchedSubjects: [BLEMatchSubject] = []
    private var sceneActive = true
    private var inactiveAt: Date?
    /// The in-flight Device Information read, owned here so scene loss or power loss can cancel it.
    private var readTask: Task<Result<BLEDeviceInfo, BLEReadError>, Never>?

    init(makeCentral: @escaping @MainActor () -> any BLECentral = { CoreBluetoothCentral() },
         authorization: @escaping () -> BLEAuthorization = BLEAuthorization.current,
         store: BLEDeviceStore, parser: BLEAdvertisementParser = BLEAdvertisementParser(),
         now: @escaping () -> Date = Date.init, publishInterval: Duration = BluetoothViewModel.publishInterval) {
        self.makeCentral = makeCentral
        self.readAuthorization = authorization
        self.store = store
        self.parser = parser
        self.now = now
        self.interval = publishInterval
        self.authorization = authorization()
        store.load()
        saved = store.devices
    }

    // MARK: Scan control

    /// The only path that may create the central while authorization is undetermined, which shows the system prompt.
    func allowAndScan(duration: TimeInterval = BluetoothViewModel.scanDuration) {
        let auth = readAuthorization()
        applyAuthorization(auth)
        guard auth == .allowed || auth == .undetermined else { return }
        requestScan(duration: duration)
    }

    /// The header path: creates the central only when authorization already reads allowed, so it never prompts.
    @discardableResult
    func startScanIfAuthorized(duration: TimeInterval = BluetoothViewModel.scanDuration) -> Bool {
        let auth = readAuthorization()
        applyAuthorization(auth)
        guard auth == .allowed else { return false }
        requestScan(duration: duration)
        return isScanning || requestedDuration != nil
    }

    /// Pull to refresh: only when Bluetooth already reads allowed, drops dimmed unsaved rows and starts a scan; never prompts.
    @discardableResult
    func refreshFromPull() -> Bool {
        guard readAuthorization() == .allowed else { return false }
        pruneDimmedUnsaved()
        return startScanIfAuthorized()
    }

    /// Drops every unsaved row unseen for `BLELifecycle.dimAfter` and republishes, so suggestions and badges follow.
    func pruneDimmedUnsaved() {
        let removed = rows.pruneDimmedUnsaved(now: now())
        guard !removed.isEmpty else { return }
        forgetRemoved(removed)
        publishNow()
    }

    /// Swipe to remove: clears one unsaved row from the list; saved rows are forgotten through their own confirmation.
    func removeFromList(_ peripheralID: UUID) {
        guard rows.removeUnsaved(peripheralID) else { return }
        forgetRemoved([peripheralID])
        publishNow()
    }

    func stopScan(reason: BLEScanEndReason) {
        requestedDuration = nil
        if reason == .powerLost { readTask?.cancel() }
        guard isScanning else { return }
        endScan(callCentral: reason != .powerLost, freeze: true)
    }

    func scenePhaseChanged(isActive: Bool) {
        guard isActive != sceneActive else { return }
        sceneActive = isActive
        if !isActive {
            inactiveAt = now()
            // No background mode: a pending connect cannot time out while suspended, so end the read now.
            readTask?.cancel()
            if isScanning { stopScan(reason: .sceneInactive) }
            return
        }
        if let since = inactiveAt { rows.shiftAging(by: max(0, now().timeIntervalSince(since))) }
        inactiveAt = nil
        rows.markAllStale()
        publishNow()
        applyAuthorization(readAuthorization())
        startIfReady()
    }

    private func requestScan(duration: TimeInterval) {
        guard !isScanning else { return }
        requestedDuration = duration
        ensureCentral()
        startIfReady()
    }

    private func ensureCentral() {
        guard central == nil else { return }
        let made = makeCentral()
        central = made
        eventsSubscription = made.events.sink { [weak self] event in self?.handle(event) }
        if made.powerState != powerState { powerState = made.powerState }
    }

    /// Starts a requested scan once power is on, the scene is active and authorization reads allowed.
    private func startIfReady() {
        guard let duration = requestedDuration, let central, !isScanning else { return }
        switch powerState {
        case .poweredOff, .unsupported:
            requestedDuration = nil
            return
        case .unknown, .resetting:
            return
        case .poweredOn:
            break
        }
        guard sceneActive else { return }
        let auth = readAuthorization()
        applyAuthorization(auth)
        guard auth == .allowed else { return }
        requestedDuration = nil
        beginScan(central, duration: duration)
    }

    private func beginScan(_ central: any BLECentral, duration: TimeInterval) {
        seenThisScan = []
        scanStartedAt = now()
        rows.markAllStale()
        central.startScan(allowDuplicates: true)
        // Set before `isScanning`, so the Device detail card shows suggestions made during the first scan.
        hasScannedThisSession = true
        isScanning = true
        publishNow()
        timeoutTask?.cancel()
        timeoutTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(duration))
            guard !Task.isCancelled else { return }
            self?.stopScan(reason: .timeout)
        }
    }

    private func endScan(callCentral: Bool, freeze: Bool) {
        timeoutTask?.cancel()
        timeoutTask = nil
        if callCentral { central?.stopScan() }
        isScanning = false
        publishNow()
        if freeze {
            summarySeen = seenThisScan
            lastScanSummary = Self.summary(seenThisScan: seenThisScan, matches: matches, now: now())
        }
        hasScannedThisSession = true
        seenThisScan = []
    }

    private func applyAuthorization(_ auth: BLEAuthorization) {
        if auth != authorization { authorization = auth }
        guard auth == .denied || auth == .restricted else { return }
        requestedDuration = nil
        if isScanning { endScan(callCentral: true, freeze: false) }
        summarySeen = []
        if lastScanSummary != nil { lastScanSummary = nil }
    }

    // MARK: Central events

    private func handle(_ event: BLECentralEvent) {
        switch event {
        case .power(let state): handlePower(state)
        case .sighting(let sighting): ingest(sighting)
        }
    }

    private func handlePower(_ state: BLEPowerState) {
        if state != powerState { powerState = state }
        applyAuthorization(readAuthorization())
        // A reset also ends CoreBluetooth's scan; it counts as power lost and the user starts again.
        if state == .poweredOff || state == .unsupported || state == .resetting {
            requestedDuration = nil
            if isScanning { stopScan(reason: .powerLost) }
        }
        startIfReady()
    }

    private func ingest(_ sighting: BLESighting) {
        let parsed = parser.parse(sighting.fields)
        let result = rows.ingest(sighting, parsed: parsed)
        let rowID = result.rowID
        if let absorbed = result.absorbed { moveBookkeeping(from: absorbed, to: rowID, identifiers: result.absorbedIdentifiers) }
        latestIdentifier[rowID] = sighting.identifier
        if let split = result.splitOff {
            latestIdentifier[split.rowID] = split.identifier
            if isScanning, let start = scanStartedAt, split.lastSeen >= start { seenThisScan.insert(split.rowID) }
            // A row folded in for this identifier is no longer this row's device.
            for (old, target) in foldedInto where target == rowID && foldedIdentifiers[old]?.contains(split.identifier) == true {
                foldedInto[old] = nil
                foldedIdentifiers[old] = nil
            }
        }
        if isScanning { seenThisScan.insert(rowID) }
        reattachSaved(rowID)
        pendingRecords.append(BLEAdvertisementRecord(sighting: sighting, parsed: parsed, peripheralID: rowID))
        scheduleTick()
    }

    /// A removed row's read target, scan membership and summary membership move to the row that absorbed it.
    private func moveBookkeeping(from removed: UUID, to survivor: UUID, identifiers: Set<UUID>) {
        foldedIdentifiers[removed] = identifiers
        latestIdentifier[survivor] = latestIdentifier[removed] ?? latestIdentifier[survivor]
        latestIdentifier[removed] = nil
        if seenThisScan.remove(removed) != nil { seenThisScan.insert(survivor) }
        if summarySeen.remove(removed) != nil { summarySeen.insert(survivor) }
        foldedInto[removed] = survivor
        for (old, target) in foldedInto where target == removed { foldedInto[old] = survivor }
        reattachSaved(survivor)
    }

    /// Gives a row its saved entry when its fingerprint is unique among rows and among saved entries.
    private func reattachSaved(_ rowID: UUID) {
        guard !saved.isEmpty,
              let row = rows.peripherals.first(where: { $0.id == rowID }), row.savedID == nil,
              let fingerprint = row.fingerprint else { return }
        let hits = saved.filter { $0.fingerprint == fingerprint }
        guard hits.count == 1, var entry = hits.first,
              rows.peripherals.filter({ $0.fingerprint == fingerprint }).count == 1,
              !rows.peripherals.contains(where: { $0.savedID == entry.id }) else { return }
        rows.setSavedID(entry.id, for: rowID)
        entry.lastSeenAt = now()
        try? store.update(entry)
        saved = store.devices
    }

    // MARK: Publishing

    private func scheduleTick() {
        guard tickTask == nil else { return }
        let interval = self.interval
        tickTask = Task { [weak self] in
            try? await Task.sleep(for: interval)
            guard !Task.isCancelled else { return }
            self?.tick()
        }
    }

    private func publishNow() {
        tickTask?.cancel()
        tick()
    }

    /// Prunes, publishes rows and the log, and re-runs the matcher only when its subjects changed.
    private func tick() {
        tickTask = nil
        let t = now()
        forgetRemoved(rows.pruneExpired(now: t))
        let before = Dictionary(uniqueKeysWithValues: rows.peripherals.map { ($0.id, $0.identifiers) })
        let folded = rows.reconcileQuietRows(now: t)
        for (removed, survivor) in folded { moveBookkeeping(from: removed, to: survivor, identifiers: before[removed] ?? []) }
        // Several folds can land on one row; read from the identifier heard most recently.
        for survivor in Set(folded.values) {
            if let row = rows.peripherals.first(where: { $0.id == survivor }),
               let newest = row.identifierTraces.max(by: { $0.value.lastSeen < $1.value.lastSeen })?.key {
                latestIdentifier[survivor] = newest
            }
        }
        if !pendingRecords.isEmpty {
            var next = log
            next.append(contentsOf: pendingRecords)
            if next.count > Self.logCapacity { next.removeFirst(next.count - Self.logCapacity) }
            pendingRecords = []
            log = next
        }
        let sorted = rows.peripherals.sorted(by: Self.displayOrder)
        if sorted != peripherals { peripherals = sorted }
        let subjects = Self.subjects(from: peripherals.filter { $0.lifecycle(now: t) != .expired })
        if subjects != matchedSubjects { rematch(subjects) }
    }

    /// Clears every per-row record of pruned rows, so no read, count or redirect points at a row that is gone.
    private func forgetRemoved(_ ids: [UUID]) {
        for id in ids {
            latestIdentifier[id] = nil
            seenThisScan.remove(id)
            summarySeen.remove(id)
            for (old, target) in foldedInto where target == id {
                foldedInto[old] = nil
                foldedIdentifiers[old] = nil
            }
        }
    }

    nonisolated static func displayOrder(_ a: BLEPeripheral, _ b: BLEPeripheral) -> Bool {
        if a.firstSeen != b.firstSeen { return a.firstSeen < b.firstSeen }
        let order = a.displayName.localizedStandardCompare(b.displayName)
        if order != .orderedSame { return order == .orderedAscending }
        return a.id.uuidString < b.id.uuidString
    }

    // MARK: Matching

    func updateLANDevices(_ devices: [DiscoveredDevice]) {
        let next = Self.candidates(from: devices)
        guard next != candidates else { return }
        candidates = next
        let t = now()
        rematch(Self.subjects(from: peripherals.filter { $0.lifecycle(now: t) != .expired }))
    }

    private func rematch(_ subjects: [BLEMatchSubject]) {
        matchedSubjects = subjects
        let table = BLEMatcher.match(subjects: subjects, candidates: candidates)
        if table != matches { matches = table }
        let ids = table.suggestedDeviceIDs
        if ids != suggestedLANDeviceIDs { suggestedLANDeviceIDs = ids }
        if var summary = lastScanSummary {
            let suggested = summarySeen.intersection(table.suggestedPeripheralIDs).count
            if suggested != summary.suggested {
                summary.suggested = suggested
                lastScanSummary = summary
            }
        }
    }

    /// Matter IDs from the `_matterc._udp` TXT `VP` key, AirPlay from `_airplay._tcp` or `_raop._tcp`, HomeKit from `_hap._tcp`.
    nonisolated static func candidates(from devices: [DiscoveredDevice]) -> [BLEMatchCandidate] {
        devices.map { device in
            let types = Set(device.bonjourServices.map(\.serviceType))
            let vp = device.bonjourServices.lazy
                .filter { $0.serviceType == "_matterc._udp" }
                .compactMap { MatterTXT.vendorProduct($0.txtRecords) }
                .first
            return BLEMatchCandidate(id: device.id, name: device.hostname, manufacturer: device.manufacturer,
                                     matterVendorID: vp?.vendorID, matterProductID: vp?.productID,
                                     hasAirPlay: types.contains("_airplay._tcp") || types.contains("_raop._tcp"),
                                     hasHomeKit: types.contains("_hap._tcp"))
        }
    }

    nonisolated static func subjects(from peripherals: [BLEPeripheral]) -> [BLEMatchSubject] {
        peripherals.map { p in
            BLEMatchSubject(id: p.id, name: p.parsed.displayName, companyName: p.parsed.companyName,
                            matterVendorID: p.parsed.matter?.vendorID, matterProductID: p.parsed.matter?.productID,
                            continuity: Set(p.parsed.continuity.compactMap(\.type)), homeKitCategory: p.parsed.homeKit?.category)
        }
    }

    /// Ties are not suggestions, so they never count.
    nonisolated static func summary(seenThisScan: Set<UUID>, matches: BLEMatchTable, now: Date) -> BluetoothSummary {
        BluetoothSummary(scannedAt: now, nearby: seenThisScan.count,
                         suggested: seenThisScan.intersection(matches.suggestedPeripheralIDs).count)
    }

    // MARK: Saved devices

    func addToDevices(_ peripheralID: UUID) {
        guard let row = rows.peripherals.first(where: { $0.id == peripheralID }), row.savedID == nil else { return }
        let entry = BLESavedDevice(peripheral: row, now: now())
        do { try store.add(entry) } catch { return }
        rows.setSavedID(entry.id, for: peripheralID)
        saved = store.devices
        publishNow()
    }

    func forgetSaved(_ id: UUID) {
        do { try store.remove(id: id) } catch { return }
        for row in rows.peripherals where row.savedID == id { rows.setSavedID(nil, for: row.id) }
        saved = store.devices
        publishNow()
    }

    func mergeSaved(_ source: UUID, into target: UUID) {
        guard source != target, saved.contains(where: { $0.id == target }) else { return }
        do { try store.merge(source, into: target) } catch { return }
        for row in rows.peripherals where row.savedID == source { rows.setSavedID(target, for: row.id) }
        saved = store.devices
        publishNow()
    }

    // MARK: Device information read

    /// Runs only when the user taps Read device info; the central connects with a 5 s timeout and always disconnects.
    func readDeviceInfo(_ requestedID: UUID) async {
        let peripheralID = foldedInto[requestedID] ?? requestedID
        guard let row = rows.peripherals.first(where: { $0.id == peripheralID }), row.readState != .reading else { return }
        // One read at a time; a second request waits for the user to try again rather than taking over the radio.
        guard readTask == nil else {
            rows.update(peripheralID) { $0.readState = .failed(.busy) }
            publishNow()
            return
        }
        guard row.parsed.kind.offersDeviceInfoRead else {
            rows.update(peripheralID) { $0.readState = .failed(.notOffered) }
            publishNow()
            return
        }
        guard let central, powerState == .poweredOn else {
            rows.update(peripheralID) { $0.readState = .failed(.poweredOff) }
            publishNow()
            return
        }
        guard let identifier = latestIdentifier[peripheralID] ?? row.identifiers.first else {
            rows.update(peripheralID) { $0.readState = .failed(.notFound) }
            publishNow()
            return
        }
        rows.update(peripheralID) { $0.readState = .reading }
        publishNow()
        let task = Task { await central.readDeviceInformation(identifier: identifier, timeout: Self.readTimeout) }
        readTask = task
        let result = await task.value
        if readTask == task { readTask = nil }
        rows.update(foldedInto[peripheralID] ?? peripheralID) { p in
            switch result {
            case .success(let info):
                p.deviceInfo = info
                p.readState = .done
            case .failure(let error):
                p.readState = .failed(error)
            }
        }
        publishNow()
    }

    // MARK: Lookups, log and widget

    /// Follows a row that was folded into another, so one device keeps one detail screen.
    func peripheral(id: UUID) -> BLEPeripheral? {
        let target = foldedInto[id] ?? id
        return peripherals.first { $0.id == target }
    }

    func clearLog() {
        pendingRecords = []
        log = []
    }

    func widgetUpdate() -> BluetoothSnapshotUpdate {
        Self.widgetUpdate(summary: lastScanSummary, authorization: authorization)
    }

    /// Computed from the emitted values, because `@Published` emits before the stored property changes.
    var widgetUpdates: AnyPublisher<BluetoothSnapshotUpdate, Never> {
        Publishers.CombineLatest($lastScanSummary, $authorization)
            .map { Self.widgetUpdate(summary: $0, authorization: $1) }
            .removeDuplicates()
            .dropFirst()
            .eraseToAnyPublisher()
    }

    /// Denied or restricted clears the widget line; no scan this session keeps the previous one.
    nonisolated static func widgetUpdate(summary: BluetoothSummary?, authorization: BLEAuthorization) -> BluetoothSnapshotUpdate {
        if authorization == .denied || authorization == .restricted { return .clear }
        guard let summary else { return .keep }
        return .set(summary)
    }
}
