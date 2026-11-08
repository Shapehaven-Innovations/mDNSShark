import Foundation

/// Google Fast Pair service data for 0xFE2C. Only the 3 byte form carries a model ID.
public struct FastPairAdvertisement: Equatable, Sendable {
    public var modelID: UInt32?
    public static let serviceUUID = "FE2C"

    public init(modelID: UInt32?) { self.modelID = modelID }

    public static func parse(serviceData: Data) -> FastPairAdvertisement? {
        let b = Array(serviceData)
        guard !b.isEmpty else { return nil }
        guard b.count == 3 else { return FastPairAdvertisement(modelID: nil) }
        return FastPairAdvertisement(modelID: UInt32(b[0]) << 16 | UInt32(b[1]) << 8 | UInt32(b[2]))
    }
}
