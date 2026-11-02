import Foundation

public enum SnapshotDecodeResult<Value>: Sendable where Value: Sendable {
    case missing
    case newer(version: Int)
    case loaded(Value)
}

extension SnapshotDecodeResult: Equatable where Value: Equatable {}

public enum SnapshotCoding {
    private struct VersionProbe: Decodable { let version: Int }

    /// Sorted keys and the default date strategy keep output stable and dates exact.
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }

    /// Reads the version first so a newer file is reported even when its body would not decode.
    public static func decodeVersioned<T: Decodable & Sendable>(_ type: T.Type, from data: Data,
                                                                supported: Int) -> SnapshotDecodeResult<T> {
        let decoder = JSONDecoder()
        guard let probe = try? decoder.decode(VersionProbe.self, from: data) else { return .missing }
        if probe.version > supported { return .newer(version: probe.version) }
        guard let value = try? decoder.decode(T.self, from: data) else { return .missing }
        return .loaded(value)
    }
}
