// swift-tools-version:6.0
import PackageDescription

// The DeviceFingerprint module deliberately has no umbrella type: individual
// signal sources (OUI lookup, UBNT/NetBIOS packet codecs, TTL/banner
// heuristics, the precedence-merge rule, and the concurrency primitives) each
// live in their own file. Don't add a `DeviceFingerprint` type — it would
// shadow the module name and block `DeviceFingerprint.merge(...)`-style
// module-qualified calls from the app target.

let package = Package(
    name: "DeviceFingerprint",
    platforms: [.iOS(.v18), .macOS(.v13)],
    products: [
        .library(name: "DeviceFingerprint", targets: ["DeviceFingerprint"])
    ],
    targets: [
        .target(name: "DeviceFingerprint"),
        .testTarget(name: "DeviceFingerprintTests", dependencies: ["DeviceFingerprint"])
    ]
)
