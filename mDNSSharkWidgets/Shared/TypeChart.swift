import SwiftUI
import WidgetKit
import WidgetSnapshot

/// Ranked bars by device type for the medium Devices widget; hidden from VoiceOver because the summary label covers it.
struct TypeChart: View {
    let types: TypeBreakdown
    let isStale: Bool

    private static let rowHeight: CGFloat = 19

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(WidgetCopy.byDeviceType)
                .font(.caption2)
                .foregroundStyle(WidgetPalette.secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
                .padding(.bottom, 2)
            Spacer(minLength: 0)
            if types.isEmpty {
                Text(WidgetCopy.noTypeData)
                    .font(.system(size: 12))
                    .foregroundStyle(WidgetPalette.secondary)
            } else {
                HStack(alignment: .top, spacing: 8) {
                    ForEach(Array(types.columns.enumerated()), id: \.offset) { _, column in
                        VStack(spacing: 0) {
                            ForEach(column, id: \.label) { row in
                                TypeBarRow(row: row, compact: types.density == .compact)
                                    .frame(height: Self.rowHeight)
                            }
                        }
                        .frame(maxWidth: .infinity)
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .opacity(isStale ? 0.6 : 1)
        .accessibilityHidden(true)
    }
}

private struct TypeBarRow: View {
    let row: TypeRow
    let compact: Bool

    var body: some View {
        if compact {
            VStack(spacing: 1) {
                HStack(spacing: 3) {
                    Image(systemName: row.symbol)
                        .font(.system(size: 9))
                        .foregroundStyle(WidgetPalette.secondary)
                        .frame(width: 11)
                    Text(row.label)
                        .font(.system(size: 9.5))
                        .foregroundStyle(WidgetPalette.text)
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                    Spacer(minLength: 0)
                    count(width: 11, size: 9.5)
                }
                bar(height: 3)
            }
        } else {
            HStack(spacing: 6) {
                Image(systemName: row.symbol)
                    .font(.system(size: 13))
                    .foregroundStyle(WidgetPalette.secondary)
                    .frame(width: 16)
                Text(row.name)
                    .font(.system(size: 11))
                    .foregroundStyle(WidgetPalette.text)
                    .lineLimit(1)
                    .minimumScaleFactor(0.7)
                    .frame(width: 62, alignment: .leading)
                bar(height: 7)
                count(width: 14, size: 11)
            }
        }
    }

    private func bar(height: CGFloat) -> some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Capsule().fill(Color.white.opacity(0.12))
                Capsule().fill(Color.white.opacity(0.9))
                    .frame(width: max(height, geo.size.width * row.fraction))
                    .widgetAccentable()
            }
        }
        .frame(height: height)
    }

    private func count(width: CGFloat, size: CGFloat) -> some View {
        Text("\(row.count)")
            .font(.system(size: size, weight: .semibold))
            .monospacedDigit()
            .foregroundStyle(WidgetPalette.text)
            .lineLimit(1)
            .minimumScaleFactor(0.7)
            .frame(width: width, alignment: .trailing)
    }
}
