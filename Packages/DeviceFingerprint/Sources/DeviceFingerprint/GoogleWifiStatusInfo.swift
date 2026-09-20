import Foundation

/// Parsed identity fields from a Google Wifi / Nest Wifi local status API
/// response (`GET /api/v1/status`). The device answering its own status
/// endpoint directly — ground-truth tier, same reasoning as
/// `JNAPHNAPInfo`.
public struct GoogleWifiStatusInfo {
    /// Board codename + per-unit serial (e.g. "MISTRAL D2C-A2A-A3R-I9R"),
    /// not human-readable. Callers must not surface this directly as a
    /// device name.
    public let hardwareId: String?
    /// Board codename (e.g. "MISTRAL" = Nest Wifi router, "GALE" = Google
    /// Wifi, "BREEZE" = Nest Wifi point) — not a friendly product name.
    /// Callers must not surface this directly as a device name.
    public let modelId: String?
    public let softwareVersion: String?
}

public enum GoogleWifiStatusParser {
    /// Parses the real (community-documented, Google doesn't publish this)
    /// response shape: `{"system":{"hardwareId":"...","modelId":"...",...},
    /// "software":{"softwareVersion":"...",...},"wan":{...}}`.
    /// Requires `hardwareId` or `modelId` — the two actual identity fields —
    /// rather than accepting any lone match, since this endpoint has no
    /// `result`/status wrapper field to gate on the way JNAP/HNAP do.
    public static func parse(_ json: Data) -> GoogleWifiStatusInfo? {
        guard let root = try? JSONSerialization.jsonObject(with: json) as? [String: Any] else {
            return nil
        }
        let system = root["system"] as? [String: Any]
        let software = root["software"] as? [String: Any]
        let hardwareId = system?["hardwareId"] as? String
        let modelId = system?["modelId"] as? String
        let softwareVersion = software?["softwareVersion"] as? String
        guard hardwareId != nil || modelId != nil else { return nil }
        return GoogleWifiStatusInfo(hardwareId: hardwareId, modelId: modelId, softwareVersion: softwareVersion)
    }
}
