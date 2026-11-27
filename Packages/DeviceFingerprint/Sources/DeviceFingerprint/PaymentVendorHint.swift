import Foundation

/// Payment and point-of-sale vendors as the bundled OUI table spells them. A host whose MAC vendor is one of these gets no active probes.
public enum PaymentVendorHint {
    /// Exact vendor strings from `oui-database.txt`, matched whole; a substring match would also hit `SQUARE D COMPANY`, `Pax AB` or `Clovertech, Inc.`.
    public static let vendorNames: Set<String> = [
        "PAX Computer Technology(Shenzhen) Ltd.",
        "Verifone, Inc.",
        "INGENICO",
        "Ingenico International",
        "INGENICO TERMINALS SAS",
        "Clover Network, Inc.",
        "Square Inc.",
        "Toast, Inc.",
        "Fujian Newland Payment Technology Co., Ltd.",
        "Fujian Newland Payment Technology Co.,Ltd.",
        "Elo touch solutions",
        "Castles Technology, Co., LTD",
        "BBPOS Limited",
        "Fujian LANDI Commercial Equipment Co.,Ltd",
        "Fujian Landi Commercial Technology Co., Ltd.",
        "Spire Payments",
        "HYPERCOM, INC.",
        "Poynt Co.",
    ]

    /// True only when `manufacturer` equals one of `vendorNames` exactly, case included.
    public static func isPaymentVendor(_ manufacturer: String) -> Bool {
        vendorNames.contains(manufacturer)
    }
}
