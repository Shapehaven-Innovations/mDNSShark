// swift-tools-version:6.0
import PackageDescription

// The WidgetSnapshot module is Foundation only and shared by the app and the widget.
// Its struct WidgetSnapshot shares the module name, so callers use unqualified names such as SnapshotStore.

let package = Package(
    name: "WidgetSnapshot",
    platforms: [.iOS(.v18), .macOS(.v13)],
    products: [
        .library(name: "WidgetSnapshot", targets: ["WidgetSnapshot"])
    ],
    targets: [
        .target(name: "WidgetSnapshot"),
        .testTarget(name: "WidgetSnapshotTests", dependencies: ["WidgetSnapshot"])
    ]
)
