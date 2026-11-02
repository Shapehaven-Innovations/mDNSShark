import SwiftUI
import WidgetKit
import WidgetSnapshot

/// The large Security widget's "Issues per scan" stacked bars; hidden from VoiceOver because the parent label speaks the list.
struct IssueChartView: View {
    let chart: IssueChart
    let isStale: Bool
    @Environment(\.widgetRenderingMode) private var mode
    @ScaledMetric(relativeTo: .caption2) private var xLabelHeight: CGFloat = 13

    static let plotHeight: CGFloat = 96
    private static let slotGap: CGFloat = 6
    private static let segmentGap: CGFloat = 2
    private static let tickGap: CGFloat = 6

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header.padding(.bottom, chart.sampleCount == 0 ? 6 : 12)
            if chart.sampleCount > 0 {
                HStack(alignment: .top, spacing: Self.tickGap) {
                    ticks
                    plot
                }
                xLabels.padding(.top, 3)
            }
            if let note = chart.note {
                Text(note)
                    .font(.caption2)
                    .foregroundStyle(WidgetPalette.tertiary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                    .padding(.top, chart.sampleCount == 0 ? 0 : 1)
            }
        }
        .opacity(isStale ? 0.6 : 1)
        // The plot height is fixed, so the chart's own labels stay at the default size to leave room for the captions.
        .dynamicTypeSize(...DynamicTypeSize.large)
        .accessibilityHidden(true)
    }

    private var header: some View {
        HStack(spacing: 8) {
            Text(WidgetCopy.issuesPerScan)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(WidgetPalette.text)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
            Spacer(minLength: 4)
            legendItem(.critical, WidgetCopy.critical)
            legendItem(.warning, WidgetCopy.warning)
        }
    }

    private func legendItem(_ kind: StatusKind, _ word: String) -> some View {
        HStack(spacing: 3) {
            Image(systemName: kind.symbol).foregroundStyle(WidgetPalette.chartColor(for: kind, mode: mode))
            Text(word).foregroundStyle(WidgetPalette.secondary)
        }
        .font(.system(size: 11, weight: .medium))
        .lineLimit(1)
    }

    /// Tick labels sit centered on their gridline; offsets keep them out of the layout.
    private var ticks: some View {
        ZStack(alignment: .topTrailing) {
            ForEach(Array(chart.ticks.enumerated()), id: \.offset) { _, tick in
                Text("\(tick)")
                    .font(.system(size: 10))
                    .monospacedDigit()
                    .foregroundStyle(WidgetPalette.secondary)
                    .lineLimit(1)
                    .fixedSize()
                    .frame(height: 12)
                    .offset(y: y(for: tick) - 6)
            }
        }
        .frame(width: tickColumnWidth, height: Self.plotHeight, alignment: .topTrailing)
    }

    private var plot: some View {
        GeometryReader { geo in
            let slotWidth = Self.slotWidth(in: geo.size.width)
            ZStack(alignment: .topLeading) {
                ForEach(Array(chart.ticks.dropFirst().enumerated()), id: \.offset) { _, tick in
                    Rectangle().fill(WidgetPalette.gridLine)
                        .frame(height: 0.5)
                        .offset(y: y(for: tick))
                }
                Rectangle().fill(WidgetPalette.baseline)
                    .frame(height: 0.5)
                    .offset(y: Self.plotHeight - 0.5)
                HStack(alignment: .bottom, spacing: Self.slotGap) {
                    ForEach(Array(chart.slots.enumerated()), id: \.offset) { index, slot in
                        column(slot, isLatest: index == chart.slots.count - 1)
                            .frame(width: slotWidth, height: Self.plotHeight, alignment: .bottom)
                    }
                }
            }
        }
        .frame(height: Self.plotHeight)
    }

    /// The left label sits under the oldest filled slot, moving left only as far as it must to keep clear of Latest.
    private var xLabels: some View {
        GeometryReader { geo in
            let plotWidth = max(0, geo.size.width - tickColumnWidth - Self.tickGap)
            let slotWidth = Self.slotWidth(in: plotWidth)
            let firstFilled = CGFloat(IssueChart.slotCount - chart.sampleCount) * (slotWidth + Self.slotGap)
            HStack(spacing: 0) {
                Color.clear.frame(width: tickColumnWidth + Self.tickGap)
                if let left = chart.leftLabel {
                    Color.clear.frame(minWidth: 0, maxWidth: firstFilled).layoutPriority(1)
                    Text(left).fixedSize()
                }
                Spacer(minLength: 8)
                Text(chart.rightLabel).fixedSize()
            }
            .font(.caption2)
            .foregroundStyle(WidgetPalette.tertiary)
            .lineLimit(1)
        }
        .frame(height: xLabelHeight)
    }

    @ViewBuilder private func column(_ slot: IssueBar?, isLatest: Bool) -> some View {
        if let bar = slot {
            VStack(spacing: 2) {
                if isLatest {
                    Text("\(bar.total)")
                        .font(.system(size: 10, weight: .semibold))
                        .monospacedDigit()
                        .foregroundStyle(WidgetPalette.secondary)
                        .lineLimit(1)
                        .fixedSize()
                }
                stack(bar)
            }
        }
    }

    /// Critical sits on the baseline and warning stacks on top; the 2pt gap comes out of the warning segment so the stack top stays literal.
    @ViewBuilder private func stack(_ bar: IssueBar) -> some View {
        if bar.total == 0 {
            Rectangle().fill(WidgetPalette.tertiary).frame(height: 2)
        } else {
            let criticalHeight = bar.criticalFraction * Self.plotHeight
            let warningHeight = bar.warningFraction * Self.plotHeight
            let gap = bar.critical > 0 && bar.warning > 0 ? Self.segmentGap : 0
            VStack(spacing: 0) {
                if bar.warning > 0 {
                    UnevenRoundedRectangle(topLeadingRadius: 3, topTrailingRadius: 3)
                        .fill(WidgetPalette.chartColor(for: .warning, mode: mode))
                        .frame(height: max(1, warningHeight - gap))
                    Color.clear.frame(height: gap)
                }
                if bar.critical > 0 {
                    UnevenRoundedRectangle(topLeadingRadius: bar.warning > 0 ? 0 : 3, topTrailingRadius: bar.warning > 0 ? 0 : 3)
                        .fill(WidgetPalette.chartColor(for: .critical, mode: mode))
                        .frame(height: criticalHeight)
                }
            }
        }
    }

    /// Distance from the plot top for a tick value, from the model's ceiling.
    private func y(for tick: Int) -> CGFloat {
        guard chart.yMax > 0 else { return Self.plotHeight }
        return Self.plotHeight * (1 - CGFloat(tick) / CGFloat(chart.yMax))
    }

    /// Wide enough for the ceiling's digits at 10pt; shared by the tick column and the x labels so they line up.
    private var tickColumnWidth: CGFloat {
        let digits = String(chart.ticks.last ?? 0).count
        return max(12, CGFloat(digits) * 6.2)
    }

    private static func slotWidth(in width: CGFloat) -> CGFloat {
        max(1, (width - slotGap * CGFloat(IssueChart.slotCount - 1)) / CGFloat(IssueChart.slotCount))
    }
}
