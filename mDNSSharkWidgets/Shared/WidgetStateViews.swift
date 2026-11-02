import SwiftUI
import WidgetKit
import WidgetSnapshot

/// Shown before the first scan; Scan is offered only where the widget has one.
struct NoScanView: View {
    var showsScan: Bool
    var isRunning: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 8) {
                WidgetMark()
                Text(WidgetCopy.noScan)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(WidgetPalette.text)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(WidgetCopy.emptyAccessibilityLabel)
            Spacer(minLength: 0)
            if showsScan { ScanButton(isRunning: isRunning) }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

/// Shown when the snapshot was written by a newer app; there is nothing to scan until the app updates.
struct NeedsUpdateView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            WidgetMark()
            Text(WidgetCopy.updateApp)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(WidgetPalette.text)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(WidgetCopy.needsUpdateAccessibilityLabel)
    }
}

/// The app's WifiGlyph at the widget size, accentable in tinted modes.
struct WidgetMark: View {
    var body: some View {
        WifiGlyph()
            .frame(width: 24, height: 18)
            .foregroundStyle(WidgetPalette.text)
            .widgetAccentable()
    }
}

private struct WidgetBackground: ViewModifier {
    @Environment(\.colorScheme) private var colorScheme

    func body(content: Content) -> some View {
        content.containerBackground(for: .widget) { WidgetPalette.gradient(dark: colorScheme == .dark) }
    }
}

extension View {
    /// The teal gradient; the system drops it in tinted modes.
    func mdnsWidgetBackground() -> some View { modifier(WidgetBackground()) }
}
