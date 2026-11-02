import SwiftUI
import WidgetKit

/// A 5pt ring that drains over the fresh hour with the scan age in the center; the stale arc is orange.
struct FreshnessRing: View {
    var fraction: Double
    var isStale: Bool
    var value: Int
    var unit: String
    var diameter: CGFloat
    @Environment(\.widgetRenderingMode) private var mode

    private var isLarge: Bool { diameter >= 100 }

    var body: some View {
        ZStack {
            Circle().stroke(WidgetPalette.ringTrack, lineWidth: 5)
            Circle()
                .trim(from: 0, to: max(0, min(1, fraction)))
                .stroke(arcColor, style: StrokeStyle(lineWidth: 5, lineCap: .round))
                .rotationEffect(.degrees(-90))
            VStack(spacing: 1) {
                Text("\(value)")
                    .font(.system(size: isLarge ? 35 : 23, weight: .bold))
                    .monospacedDigit()
                    .foregroundStyle(WidgetPalette.text)
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)
                Text(unit)
                    .font(.system(size: isLarge ? 16 : 10))
                    .foregroundStyle(WidgetPalette.secondary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)
            }
            .padding(6)
        }
        .frame(width: diameter, height: diameter)
        .accessibilityHidden(true)
    }

    private var arcColor: Color {
        if WidgetPalette.isTinted(mode) { return .white }
        return isStale ? WidgetPalette.warning : .white
    }
}
