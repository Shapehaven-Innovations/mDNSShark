import Foundation

public struct BannerGuess {
    public let manufacturer: String?
    public let os: String?
}

/// Cheap substring matching over a raw TCP banner (SSH version string, HTTP
/// Server header, etc). Weak evidence, same tier as the TTL guess — never
/// treat this as certain.
public func guessFromBanner(_ banner: String) -> BannerGuess {
    let lower = banner.lowercased()
    var manufacturer: String?
    var os: String?

    if lower.contains("dropbear") {
        os = "Linux (embedded, likely)"
    } else if lower.contains("openssh") && (lower.contains("debian") || lower.contains("ubuntu")) {
        os = "Linux (likely)"
    } else if lower.contains("openssh") {
        os = "Linux/Unix-like (likely)"
    }

    if lower.contains("synology") {
        manufacturer = "Synology"
    } else if lower.contains("ubiquiti") || lower.contains("unifi") {
        manufacturer = "Ubiquiti"
    } else if lower.contains("mikrotik") || lower.contains("routeros") {
        manufacturer = "MikroTik"
    } else if lower.contains("linksys") {
        manufacturer = "Linksys"
    } else if lower.contains("tp-link") || lower.contains("tplink") {
        manufacturer = "TP-Link"
    } else if lower.contains("gl.inet") || lower.contains("gl-inet") {
        manufacturer = "GL.iNet"
    } else if lower.contains("netgear") {
        manufacturer = "Netgear"
    } else if lower.contains("asus") {
        // Specific-before-generic: "asus" alone can false-positive on words
        // like "pegasus" (same accepted risk class as "unifi"/"unified"
        // above), so it's checked last, after all more specific vendor
        // strings that can't collide this way.
        manufacturer = "ASUS"
    }

    // LuCI is OpenWrt's stock web UI, used by GL.iNet and many other
    // OpenWrt-based vendors generically - it's a real OS-family signal even
    // when it doesn't identify a specific manufacturer on its own.
    if os == nil, lower.contains("luci") {
        os = "Linux (OpenWrt, likely)"
    }

    return BannerGuess(manufacturer: manufacturer, os: os)
}
