import SwiftUI
import WidgetKit
import WidgetSnapshot

/// Widget colors. The status hex values mirror the app's status colors, which are app-only, and pin contrast on the teal gradient.
enum WidgetPalette {
    static let text = Color(hex: 0xFAFAFA)
    static let secondary = Color.white.opacity(0.72)
    static let tertiary = Color.white.opacity(0.5)
    static let secure = Color(hex: 0x34C759)
    static let warning = Color(hex: 0xFF9F0A)
    static let critical = Color(hex: 0xFF3B30)
    static let ringTrack = Color.white.opacity(0.14)
    static let scanFill = Color.white.opacity(0.18)
    static let scanStroke = Color.white.opacity(0.28)

    /// 160 degree gradient from the mockup, lighter at the top left.
    static func gradient(dark: Bool) -> LinearGradient {
        let colors = dark ? [Color(hex: 0x14525C), Color(hex: 0x00171F)] : [Color(hex: 0x246B78), Color(hex: 0x032E36)]
        return LinearGradient(colors: colors, startPoint: UnitPoint(x: 0.33, y: 0), endPoint: UnitPoint(x: 0.67, y: 1))
    }

    static func tileFill(dark: Bool) -> Color { Color.white.opacity(dark ? 0.10 : 0.14) }

    /// Full color uses the status hex; tinted modes use white opacities. Outlined kinds are tertiary in both.
    static func color(for kind: StatusKind, mode: WidgetRenderingMode) -> Color {
        if kind.isOutlined { return tertiary }
        let tinted = mode == .accented || mode == .vibrant
        switch kind {
        case .secure: return tinted ? .white : secure
        case .warning: return tinted ? .white.opacity(0.72) : warning
        case .critical: return tinted ? .white.opacity(0.5) : critical
        case .notProbed, .pending: return tertiary
        }
    }

    static func isTinted(_ mode: WidgetRenderingMode) -> Bool { mode == .accented || mode == .vibrant }
}

extension Color {
    init(hex: UInt32) {
        self.init(red: Double((hex >> 16) & 0xFF) / 255, green: Double((hex >> 8) & 0xFF) / 255,
                  blue: Double(hex & 0xFF) / 255)
    }
}
