import AppIntents
import SwiftUI
import WidgetKit
import WidgetSnapshot

/// The interactive Scan capsule; its intent hands the scan to the app process, never scanning in the widget.
struct ScanButton: View {
    enum Size {
        case compact, large

        var height: CGFloat { self == .compact ? 26 : 30 }
        var fontSize: CGFloat { self == .compact ? 12 : 15 }
        var padding: CGFloat { self == .compact ? 11 : 14 }
    }

    var isRunning: Bool
    var size: Size = .compact
    var fullWidth: Bool = false

    var body: some View {
        Group {
            if #available(iOS 26.0, *), WidgetScanIntentChoice.runsInBackground {
                Button(intent: BackgroundScanIntent()) { label }
            } else {
                Button(intent: ScanNowIntent()) { label }
            }
        }
        .buttonStyle(.plain)
        .invalidatableContent()
        .widgetAccentable()
        .accessibilityLabel(WidgetCopy.scanAccessibilityLabel)
    }

    private var label: some View {
        HStack(spacing: 5) {
            if isRunning {
                ProgressView().controlSize(.mini).tint(WidgetPalette.text)
            } else {
                Image(systemName: "arrow.clockwise")
            }
            Text(WidgetCopy.scan)
        }
        .font(.system(size: size.fontSize, weight: .semibold))
        .foregroundStyle(WidgetPalette.text)
        .padding(.horizontal, size.padding)
        .frame(maxWidth: fullWidth ? .infinity : nil)
        .frame(height: size.height)
        .background(Capsule().fill(WidgetPalette.scanFill))
        .overlay(Capsule().strokeBorder(WidgetPalette.scanStroke, lineWidth: 0.5))
        .opacity(isRunning ? 0.7 : 1)
    }
}
