import Foundation

/// Cheap, curated manufacturer-name -> likely-OS-family inference, shared
/// by `guessFromBanner` (banner-text-derived manufacturer) and `merge()`
/// (any-source-derived manufacturer — including an OUI lookup, which can
/// resolve to any of thousands of unrelated companies: laptops, phones,
/// printers, etc).
///
/// Deliberately scoped to router/AP/NAS-class vendors only, and safe to
/// call with ANY manufacturer string for exactly that reason — it returns
/// nil for anything not in this curated list rather than guessing at
/// vendors where "embedded Linux" would be a wrong assumption (e.g.
/// "Apple, Inc.", "Dell Inc.", "Samsung Electronics" are all real OUI
/// matches this app can see, and none of them run embedded router
/// firmware). Same "likely", never-certain tier as every other guess in
/// this module.
public func inferredOSFamily(forManufacturer manufacturer: String) -> String? {
    let lower = manufacturer.lowercased()

    if lower.contains("synology") {
        return "DSM (Synology, Linux-based, likely)"
    }
    if lower.contains("mikrotik") {
        return "RouterOS (MikroTik, Linux-based, likely)"
    }

    let genericEmbeddedLinuxVendors = [
        "ubiquiti", "linksys", "tp-link", "tplink", "gl.inet", "gl-inet", "netgear", "asus"
    ]
    if genericEmbeddedLinuxVendors.contains(where: lower.contains) {
        return "Linux (embedded, likely)"
    }

    return nil
}
