import Foundation

/// Traffic-control, roadside, tolling, detection and licence plate equipment vendors as the bundled OUI table spells them. A host whose MAC vendor is one of these gets no active probes.
public enum InfrastructureVendorHint {
    /// Exact vendor strings from `oui-database.txt`, matched whole, so ambiguous names such as `Kapsch Ag` or `FLIR Systems` are left out on purpose.
    public static let vendorNames: Set<String> = [
        "Econolite Control Products, Inc.",
        "Peek Traffic B.V.",
        "McCain Inc",
        "Siemens AG, Transportation Systems",
        "Eagle Traffic Control Systems",
        "Q-Free ASA",
        "Q-Free America, Inc.",
        "Swarco LEA d.o.o.",
        "Lacroix Traffic S.A.U",
        "Northwest Signal Supply, Inc",
        "Global Traffic Technologies, LLC",
        "NoTraffic",
        "Iteris, Inc.",
        "Wavetronix",
        "Image Sensing Systems, Inc.",
        "Sensys Traffic AB",
        "Miovision Technologies Incorporated",
        "TrafficCast International",
        "Missouri Department of Transportation",
        "TransCore",
        "Neology",
        "Cubic Transportation Systems Inc",
        "Gatsometer",
        "Flock Safety",
        "Adaptive Recognition Hungary, Inc",
    ]

    /// True only when `manufacturer` equals one of `vendorNames` exactly, case included.
    public static func isInfrastructureVendor(_ manufacturer: String) -> Bool {
        vendorNames.contains(manufacturer)
    }
}
