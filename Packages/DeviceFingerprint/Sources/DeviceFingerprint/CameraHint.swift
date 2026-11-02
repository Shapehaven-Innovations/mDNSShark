import Foundation

/// Camera-evidence checks over data the app already holds. Each answers only "is this camera-class", never which model, and none sends traffic.
public enum CameraHint {
    /// Vendor-name prefixes that make only cameras, recorders and doorbells. Anchored at the start of the name: a substring such as "arlo" or "blink" also hits unrelated vendors.
    private static let vendorPrefixes = [
        "hangzhou hikvision", "prama hikvision", "hikvision",
        "zhejiang dahua", "dahua", "hangzhou huacheng", "hangzhou ezviz", "ezviz",
        "amcrest", "axis communications", "reolink", "zhejiang uniview", "xiamen milesight",
        "tvt co", "zhuhai raysharp", "lorex", "swann communications", "vivotek", "mobotix",
        "geovision", "hanwha vision", "samsung techwin", "verkada", "ring llc",
        "blink by amazon", "wyze labs", "arlo technology", "nest labs", "xiongmai",
        "flock safety", "adaptive recognition", "avigilon",
    ]

    /// True for a manufacturer name that belongs to a camera-only vendor. TP-Link, Ubiquiti and Anker also make cameras but mostly other gear, so they are left out.
    public static func isCameraVendor(_ manufacturer: String) -> Bool {
        let lower = manufacturer.lowercased()
        return vendorPrefixes.contains { lower.hasPrefix($0) }
    }

    /// Bonjour types that only cameras, recorders and their management software advertise. Accepts the full type ("_rtsp._tcp") or the bare first label.
    private static let serviceTypes: Set<String> = [
        "_axis-video", "_axis-nvr", "_acsp-server", "_rtsp", "_psia", "_cctv", "_amba-cam",
    ]

    public static func isCameraServiceType(_ type: String) -> Bool {
        serviceTypes.contains(String(type.prefix { $0 != "." }).lowercased())
    }

    /// Amcrest and Dahua name their `_http._tcp` instance `AMC` plus the serial, and Hikvision starts its with the brand.
    public static func isCameraInstanceName(_ name: String) -> Bool {
        let lower = name.lowercased()
        if lower.hasPrefix("hikvision") { return true }
        guard lower.hasPrefix("amc") else { return false }
        let serial = lower.dropFirst(3).prefix { $0.isHexDigit }
        return serial.count >= 12
    }

    /// HomeKit category id from `_hap._tcp` TXT `ci`: 17 is an IP camera and 18 a video doorbell.
    public static func isCameraHAPCategory(_ ci: String) -> Bool {
        ci == "17" || ci == "18"
    }

    /// Matter device type from `_matterc._udp` TXT `DT` (decimal): camera 0x142, video doorbell 0x143, floodlight camera 0x144, snapshot camera 0x145.
    public static func isCameraMatterDeviceType(_ dt: String) -> Bool {
        guard let value = Int(dt) else { return false }
        return (0x142...0x145).contains(value)
    }

    /// One discovery row's evidence: a camera-only vendor, a camera service type or instance name, a HomeKit camera category, or a Matter camera device type.
    public static func rowLooksLikeCamera(manufacturer: String?, serviceType: String, serviceName: String, txtRecords: [String: String]?) -> Bool {
        if let manufacturer, isCameraVendor(manufacturer) { return true }
        return isCameraServiceType(serviceType) || isCameraInstanceName(serviceName)
            || (serviceType == "_hap._tcp" && txtRecords?["ci"].map(isCameraHAPCategory) == true)
            || (serviceType == "_matterc._udp" && txtRecords?["DT"].map(isCameraMatterDeviceType) == true)
    }
}
