import Foundation

public struct SnapshotStore: Sendable {
    public static let snapshotFile = "widget-snapshot.json"
    public static let captureFile = "widget-capture.json"
    public static let seenFile = "widget-seen.json"

    public let directory: URL

    public init(directory: URL) {
        self.directory = directory
    }

    public static func appGroup() -> SnapshotStore? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AppGroup.identifier)
            .map { SnapshotStore(directory: $0) }
    }

    public func loadSnapshot() -> SnapshotDecodeResult<WidgetSnapshot> {
        load(WidgetSnapshot.self, file: Self.snapshotFile, supported: WidgetSnapshot.schemaVersion)
    }

    public func save(_ snapshot: WidgetSnapshot) throws {
        try write(SnapshotCoding.encode(snapshot.trimmedToFit()), file: Self.snapshotFile)
    }

    public func loadCapture() -> SnapshotDecodeResult<CaptureSummary> {
        load(CaptureSummary.self, file: Self.captureFile, supported: CaptureSummary.schemaVersion)
    }

    public func save(_ capture: CaptureSummary) throws {
        try write(SnapshotCoding.encode(capture), file: Self.captureFile)
    }

    public func loadSeen() -> [String: Date] {
        guard let data = try? Data(contentsOf: directory.appendingPathComponent(Self.seenFile)),
              let seen = try? JSONDecoder().decode([String: Date].self, from: data) else { return [:] }
        return seen
    }

    public func saveSeen(_ seen: [String: Date]) throws {
        try write(SnapshotCoding.encode(seen), file: Self.seenFile)
    }

    private func load<T: Decodable & Sendable>(_ type: T.Type, file: String, supported: Int) -> SnapshotDecodeResult<T> {
        guard let data = try? Data(contentsOf: directory.appendingPathComponent(file)) else { return .missing }
        return SnapshotCoding.decodeVersioned(type, from: data, supported: supported)
    }

    private func write(_ data: Data, file: String) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try data.write(to: directory.appendingPathComponent(file), options: .atomic)
    }
}
