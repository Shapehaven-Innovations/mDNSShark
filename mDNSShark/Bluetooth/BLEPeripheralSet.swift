import Foundation
import DeviceFingerprint

/// The session's peripheral rows. Pure value type; the view model owns one and publishes it.
struct BLEPeripheralSet: Equatable {
    private(set) var peripherals: [BLEPeripheral] = []

    init() {}

    /// What one sighting did to the rows, so the view model can move its per-row bookkeeping.
    struct IngestResult {
        /// The row that now holds the sighting's identifier.
        var rowID: UUID
        /// A row split off because two identifiers of one row were heard at the same time, with when it was last heard.
        var splitOff: (rowID: UUID, identifier: UUID, lastSeen: Date)?
        /// A row removed because it turned out to be `rowID` under a new identifier.
        var absorbed: UUID?
        /// The identifiers the removed row held.
        var absorbedIdentifiers: Set<UUID> = []
    }

    /// CoreBluetooth reports 127 when no RSSI is available; anything above this is no reading.
    static let maxValidRSSI = 20
    /// The value a new row gets when its first sighting has no reading, so it sorts last and reads Far.
    static let noReadingFloor = -127
    /// An older identifier still heard this long after a newer one joined means two devices, not a rotation.
    static let splitGrace: TimeInterval = 2
    /// How long a row must be silent before a same-fingerprint row born after it is folded into it.
    static let quietThreshold: TimeInterval = 10

    @discardableResult
    mutating func ingest(_ sighting: BLESighting, parsed: BLEParsedAdvertisement) -> IngestResult {
        if let index = peripherals.firstIndex(where: { $0.identifierTraces[sighting.identifier] != nil }) {
            return updateHeldRow(at: index, sighting, parsed: parsed)
        }
        if let fingerprint = BLEFingerprint(parsed: parsed) {
            let same = peripherals.indices.filter { peripherals[$0].fingerprint == fingerprint }
            if same.count == 1 {
                Self.apply(sighting, parsed: parsed, to: &peripherals[same[0]])
                return IngestResult(rowID: peripherals[same[0]].id)
            }
        }
        let valid = sighting.rssi <= Self.maxValidRSSI
        var history = RSSIRingBuffer()
        if valid { history.append(sighting.rssi) }
        let rssi = valid ? sighting.rssi : Self.noReadingFloor
        let row = BLEPeripheral(id: UUID(),
                                identifierTraces: [sighting.identifier: IdentifierTrace(joinedAt: sighting.at, lastSeen: sighting.at, lastRSSI: rssi)],
                                parsed: parsed, fields: sighting.fields, rssi: rssi, rssiHistory: history,
                                firstSeen: sighting.at, lastSeen: sighting.at, agingAnchor: sighting.at,
                                markedStale: false, savedID: nil, deviceInfo: nil, readState: .idle)
        peripherals.append(row)
        return IngestResult(rowID: row.id)
    }

    /// Splits off the newest identifier when an older one is still heard, then absorbs a row whose name just arrived.
    private mutating func updateHeldRow(at index: Int, _ sighting: BLESighting, parsed: BLEParsedAdvertisement) -> IngestResult {
        var splitOff: (rowID: UUID, identifier: UUID, lastSeen: Date)?
        let row = peripherals[index]
        if let newest = row.newestIdentifier, newest != sighting.identifier, let trace = row.identifierTraces[newest],
           sighting.at >= trace.joinedAt.addingTimeInterval(Self.splitGrace) {
            var history = RSSIRingBuffer()
            if trace.lastRSSI != Self.noReadingFloor { history.append(trace.lastRSSI) }
            let off = BLEPeripheral(id: UUID(), identifierTraces: [newest: trace], parsed: row.parsed, fields: row.fields,
                                    rssi: trace.lastRSSI, rssiHistory: history, firstSeen: trace.joinedAt,
                                    lastSeen: trace.lastSeen, agingAnchor: trace.lastSeen, markedStale: row.markedStale,
                                    savedID: nil, deviceInfo: nil, readState: .idle)
            peripherals[index].identifierTraces[newest] = nil
            peripherals.append(off)
            splitOff = (off.id, newest, trace.lastSeen)
        }
        let before = peripherals[index].fingerprint
        Self.apply(sighting, parsed: parsed, to: &peripherals[index])
        let rowID = peripherals[index].id
        guard before == nil, let after = peripherals[index].fingerprint else {
            return IngestResult(rowID: rowID, splitOff: splitOff)
        }
        let others = peripherals.indices.filter { $0 != index && peripherals[$0].fingerprint == after }
        guard others.count == 1 else { return IngestResult(rowID: rowID, splitOff: splitOff) }
        let donor = peripherals[index]
        let survivor = others[0]
        Self.absorb(donor, into: &peripherals[survivor], rejoinAt: donor.firstSeen)
        let survivorID = peripherals[survivor].id
        peripherals.remove(at: index)
        return IngestResult(rowID: survivorID, splitOff: splitOff, absorbed: donor.id, absorbedIdentifiers: donor.identifiers)
    }

    /// Folds a row born after a quiet same-fingerprint row went silent into that quiet row; returns removed -> survivor.
    @discardableResult
    mutating func reconcileQuietRows(now: Date, quiet: TimeInterval = BLEPeripheralSet.quietThreshold) -> [UUID: UUID] {
        var folded: [UUID: UUID] = [:]
        var i = 0
        while i < peripherals.count {
            let quietRow = peripherals[i]
            guard let fingerprint = quietRow.fingerprint, now.timeIntervalSince(quietRow.lastSeen) >= quiet else {
                i += 1
                continue
            }
            let bornAfter = quietRow.lastSeen.addingTimeInterval(-Self.splitGrace)
            let successors = peripherals.indices.filter {
                $0 != i && peripherals[$0].fingerprint == fingerprint && peripherals[$0].firstSeen >= bornAfter
            }
            guard let j = successors.min(by: { peripherals[$0].firstSeen < peripherals[$1].firstSeen }) else {
                i += 1
                continue
            }
            let donor = peripherals[j]
            Self.absorb(donor, into: &peripherals[i], rejoinAt: nil)
            for (removed, survivor) in folded where survivor == donor.id { folded[removed] = quietRow.id }
            folded[donor.id] = quietRow.id
            peripherals.remove(at: j)
            if j < i { i -= 1 }
        }
        return folded
    }

    /// The survivor keeps its id, first sighting and saved entry and takes the donor's identifiers and latest state.
    private static func absorb(_ donor: BLEPeripheral, into survivor: inout BLEPeripheral, rejoinAt: Date?) {
        let donorNewest = donor.newestIdentifier
        for (identifier, var trace) in donor.identifierTraces {
            if let rejoinAt { trace.joinedAt = rejoinAt }
            survivor.identifierTraces[identifier] = trace
        }
        survivor.lastJoined = donorNewest ?? survivor.lastJoined
        survivor.lastSeen = donor.lastSeen
        survivor.agingAnchor = donor.agingAnchor
        survivor.rssi = donor.rssi
        survivor.rssiHistory = donor.rssiHistory
        survivor.fields = donor.fields
        survivor.parsed = donor.parsed
        survivor.markedStale = donor.markedStale
        survivor.savedID = survivor.savedID ?? donor.savedID
        survivor.deviceInfo = survivor.deviceInfo ?? donor.deviceInfo
        // A read running on the donor still finishes onto this row, so the row keeps showing it.
        if donor.readState == .reading { survivor.readState = .reading }
    }

    /// Records the sighting on the row. Every field the fingerprint reads is sticky: a frame that lacks the name,
    /// the Matter IDs, the Fast Pair model or the company keeps the last value heard, so one row keeps one fingerprint.
    private static func apply(_ sighting: BLESighting, parsed: BLEParsedAdvertisement, to row: inout BLEPeripheral) {
        let valid = sighting.rssi <= maxValidRSSI
        var fields = sighting.fields
        var parsed = parsed
        if fields.localName == nil { fields.localName = row.fields.localName }
        if parsed.displayName == nil { parsed.displayName = row.parsed.displayName }
        if parsed.matter == nil { parsed.matter = row.parsed.matter }
        if parsed.fastPair?.modelID == nil, row.parsed.fastPair?.modelID != nil { parsed.fastPair = row.parsed.fastPair }
        if parsed.companyID == nil {
            parsed.companyID = row.parsed.companyID
            parsed.companyName = row.parsed.companyName
        }
        if var trace = row.identifierTraces[sighting.identifier] {
            trace.lastSeen = sighting.at
            if valid { trace.lastRSSI = sighting.rssi }
            row.identifierTraces[sighting.identifier] = trace
        } else {
            row.identifierTraces[sighting.identifier] = IdentifierTrace(joinedAt: sighting.at, lastSeen: sighting.at,
                                                                        lastRSSI: valid ? sighting.rssi : row.rssi)
            row.lastJoined = sighting.identifier
        }
        row.fields = fields
        row.parsed = parsed
        if valid {
            row.rssi = sighting.rssi
            row.rssiHistory.append(sighting.rssi)
        }
        row.lastSeen = sighting.at
        row.agingAnchor = sighting.at
        row.markedStale = false
    }

    mutating func markAllStale() {
        for i in peripherals.indices { peripherals[i].markedStale = true }
    }

    /// Moves every aging anchor forward so time spent away from a scan does not age rows; `lastSeen` is untouched.
    mutating func shiftAging(by interval: TimeInterval) {
        for i in peripherals.indices { peripherals[i].agingAnchor = peripherals[i].agingAnchor.addingTimeInterval(interval) }
    }

    /// Removes expired rows that are not saved and returns their ids.
    mutating func pruneExpired(now: Date) -> [UUID] {
        let removed = peripherals.filter { $0.savedID == nil && $0.lifecycle(now: now) == .expired }.map(\.id)
        if !removed.isEmpty { peripherals.removeAll { removed.contains($0.id) } }
        return removed
    }

    /// Removes unsaved rows already dimmed by age (unseen for `BLELifecycle.dimAfter`) and returns their ids; saved rows stay.
    mutating func pruneDimmedUnsaved(now: Date) -> [UUID] {
        let removed = peripherals.filter { $0.savedID == nil && now.timeIntervalSince($0.agingAnchor) >= BLELifecycle.dimAfter }.map(\.id)
        if !removed.isEmpty { peripherals.removeAll { removed.contains($0.id) } }
        return removed
    }

    /// Applies `body` to the row with this id, if it is still held.
    mutating func update(_ id: UUID, _ body: (inout BLEPeripheral) -> Void) {
        guard let i = peripherals.firstIndex(where: { $0.id == id }) else { return }
        body(&peripherals[i])
    }

    mutating func setSavedID(_ savedID: UUID?, for id: UUID) {
        guard let i = peripherals.firstIndex(where: { $0.id == id }) else { return }
        peripherals[i].savedID = savedID
    }
}
