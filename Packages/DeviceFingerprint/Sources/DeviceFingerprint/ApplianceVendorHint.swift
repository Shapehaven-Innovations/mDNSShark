import Foundation

/// Appliance, home-energy and home-control makers as the bundled OUI table spells them. A match is a vendor fact from the MAC, not proof of the device type.
public enum ApplianceVendorHint {
    /// Exact vendor strings from `oui-database.txt`, matched whole and case-sensitively; a substring match would hit `Carrier Access Corporation` or `Genie Industries, Inc.`.
    public static let vendorNames: Set<String> = [
        // Laundry and cooking
        "BSH Hausgeräte GmbH", "BSH Electrical Appliances (Jiangsu) Co., Ltd.", "Miele & Cie. KG", "Whirlpool Corporation", "Electrolux",
        "GE Appliances", "Sub-Zero Group, Inc.", "Panasonic Appliances Company",
        // Climate and water
        "GD Midea Air-Conditioning Equipment Co.,Ltd.", "Midea Group Co., Ltd.", "Gree Electric Appliances, Inc. Of Zhuhai",
        "Daikin Industries, Ltd.", "Daikin Europe NV", "Daikin Air-conditioning (Shanghai) Co., Ltd.", "Daikin Holdings Singapore Pte Ltd",
        "Trane", "Trane Technologies", "GoodMan Corporation", "Bosch Thermotechnik GmbH", "Vaillant GmbH", "Viessmann Elektronik GmbH",
        "Rinnai", "Rinnai Korea", "A.O. Smith Water Products", "Rheem Australia Pty Ltd", "Dyson Limited", "Winix Co., Ltd", "Balboa Instruments",
        // Cleaning
        "iRobot Corporation", "Beijing Roborock Technology Co., Ltd.", "Dreame Technology (Suzhou) Limited", "SharkNinja", "SharkNinja Operating LLC",
        "Foshan VIOMI Electric Appliance Technology Co. Ltd.",
        // Energy
        "Enphase Energy", "SolarEdge Technologies", "Fronius Schweissmaschinen", "SMA Solar Technology AG", "Sungrow Power Supply Co.,Ltd.",
        "GoodWe Technologies CO., Ltd", "Victron Bv", "Sense Labs, Inc.",
        // Home control
        "ecobee inc", "Resideo", "tado GmbH", "The Chamberlain Group, Inc", "Kwikset", "August Home, Inc.", "Allegion PLC", "Orbit Irrigation",
        "Rain Bird Corporation", "Husqvarna AB",
        // Grills and other
        "Weber-Stephen Products LLC", "Apption Labs Limited", "Apption Labs Ltd", "Eight Sleep",
        // Venue tier, a weaker claim
        "Winterhalter Gastronom GmbH", "Rational", "Copeland LP", "Liebherr - Elektronik GmbH",
    ]

    /// True only when `manufacturer` equals one of `vendorNames` exactly, case included.
    public static func isApplianceVendor(_ manufacturer: String) -> Bool {
        vendorNames.contains(manufacturer)
    }
}
