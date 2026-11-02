import SwiftUI
import WidgetKit
import WidgetSnapshot

/// One 8pt bar split by status; widths follow counts, each segment keeps at least 6pt.
struct StatusCapsule: View {
    var segments: [CapsuleSegment]
    @Environment(\.widgetRenderingMode) private var mode

    private static let gap: CGFloat = 2
    private static let minWidth: CGFloat = 6

    var body: some View {
        GeometryReader { geo in
            let widths = Self.widths(for: segments, in: geo.size.width)
            HStack(spacing: Self.gap) {
                ForEach(Array(segments.enumerated()), id: \.offset) { index, segment in
                    piece(segment).frame(width: widths[index])
                }
            }
        }
        .frame(height: 8)
        .accessibilityHidden(true)
    }

    @ViewBuilder private func piece(_ segment: CapsuleSegment) -> some View {
        if segment.kind.isOutlined {
            Capsule().strokeBorder(WidgetPalette.tertiary, lineWidth: 1.5)
        } else {
            Capsule().fill(WidgetPalette.color(for: segment.kind, mode: mode))
        }
    }

    /// Reserves the gaps and the minimum widths first, then shares the rest by count.
    static func widths(for segments: [CapsuleSegment], in width: CGFloat) -> [CGFloat] {
        guard !segments.isEmpty else { return [] }
        let n = CGFloat(segments.count)
        let available = max(0, width - gap * (n - 1))
        let total = CGFloat(segments.reduce(0) { $0 + $1.count })
        let spare = available - minWidth * n
        guard spare > 0, total > 0 else { return segments.map { _ in available / n } }
        return segments.map { minWidth + spare * CGFloat($0.count) / total }
    }
}
