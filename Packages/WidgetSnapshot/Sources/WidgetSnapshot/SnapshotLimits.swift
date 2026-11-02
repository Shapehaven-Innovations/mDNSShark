import Foundation

extension WidgetSnapshot {
    public static let historyLimit = 12
    public static let newDevicesLimit = 6
    public static let topologyLimit = 12
    public static let maxBytes = 65_536

    /// Appends a sample (newest last) and keeps only the newest `historyLimit`.
    public static func appending(_ sample: ScanSample, to history: [ScanSample]) -> [ScanSample] {
        Array((history + [sample]).suffix(historyLimit))
    }

    /// Drops topology nodes, then new devices, then the oldest history until the encoding fits.
    public func trimmedToFit(maxBytes: Int = WidgetSnapshot.maxBytes) -> WidgetSnapshot {
        var copy = self
        func size(_ s: WidgetSnapshot) -> Int { (try? SnapshotCoding.encode(s).count) ?? 0 }
        while size(copy) > maxBytes {
            if !copy.topology.isEmpty {
                copy.topology.removeLast()
                copy.topologyOverflow += 1
            } else if !copy.newDevices.isEmpty {
                copy.newDevices.removeLast()
            } else if !copy.history.isEmpty {
                copy.history.removeFirst()
            } else {
                break
            }
        }
        return copy
    }
}

public enum SeenMap {
    public static let limit = 512

    /// Keeps first sightings and stamps new keys with `now`. Over the limit, absent keys go first (oldest, then key order) so long-lived devices are never re-reported as new.
    public static func updated(_ seen: [String: Date], present: [String], now: Date) -> [String: Date] {
        var map = seen
        for key in present where map[key] == nil { map[key] = now }
        let presentSet = Set(present)
        while map.count > limit {
            let absent = map.filter { !presentSet.contains($0.key) }
            let pool = absent.isEmpty ? map : absent
            guard let victim = pool.min(by: { ($0.value, $0.key) < ($1.value, $1.key) }) else { break }
            map.removeValue(forKey: victim.key)
        }
        return map
    }
}
