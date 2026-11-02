import Foundation

/// Camera ports the scanner only connects to or listens on, and the raw-byte matcher for port 8000's first-speaker banner.
public enum CameraPortBanner {
    /// Ports opened with no bytes written and none read, scanned only for a host that already looks like a camera.
    public static let connectOnlyPorts = [8554, 37777, 34567, 2020, 9000, 1935, 7441]

    /// First 16 bytes a Hikvision control port sends unprompted. The `0d` variant needs a client probe and is deliberately not matched.
    static let hikvisionControlPrefix: [UInt8] = [0, 0, 0, 0x10, 0, 0, 0, 0x1e, 0, 0, 0, 0x1e, 0, 0, 0, 0]

    public static let hikvisionControlLabel = "Hikvision camera control port (binary banner)"

    /// Matches on the raw bytes, never a decoded String; a truncated or different banner returns nil.
    public static func label(port8000 data: Data) -> String? {
        data.starts(with: hikvisionControlPrefix) ? hikvisionControlLabel : nil
    }
}
