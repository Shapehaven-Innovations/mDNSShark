import SwiftUI
import WidgetKit
import WidgetSnapshot

/// Scan Now: how fresh the last scan is as a draining ring, with a full width Scan button.
struct ScanNowWidget: Widget {
    let kind = WidgetKind.scan

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: kind, provider: SnapshotTimelineProvider()) { entry in
            ScanNowWidgetView(entry: entry)
        }
        .configurationDisplayName("Scan Now")
        .description("How fresh your last scan is, with a Scan button.")
        .supportedFamilies([.systemSmall, .systemMedium])
    }
}

struct ScanNowWidgetView: View {
    let entry: SnapshotEntry
    @Environment(\.widgetFamily) private var family

    var body: some View {
        content
            .mdnsWidgetBackground()
            .widgetURL(WidgetLink.devicesTab)
            .dynamicTypeSize(...DynamicTypeSize.accessibility1)
    }

    @ViewBuilder private var content: some View {
        switch ScanNowWidgetModel.make(entry.result, now: entry.date, isScanRunning: entry.isScanRunning) {
        case .noScan: NoScanView(showsScan: true, isRunning: entry.isScanRunning)
        case .needsUpdate: NeedsUpdateView()
        case .loaded(let model):
            if family == .systemMedium { ScanNowMedium(model: model) } else { ScanNowSmall(model: model) }
        }
    }
}

private struct ScanNowSmall: View {
    let model: ScanNowWidgetModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 0) {
                ScanNowTitle(isStale: model.isStale, title: model.title, font: .system(size: 15, weight: .semibold),
                             freshColor: WidgetPalette.text)
                Spacer(minLength: 4)
                HStack(spacing: 12) {
                    FreshnessRing(fraction: model.ringFraction, isStale: model.isStale, value: model.ringValue,
                                  unit: model.ringUnit, diameter: 68)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("\(model.total)")
                            .font(.system(size: 24, weight: .bold))
                            .monospacedDigit()
                            .foregroundStyle(WidgetPalette.text)
                            .lineLimit(1)
                            .minimumScaleFactor(0.6)
                            .opacity(model.isStale ? 0.6 : 1)
                        Text(model.smallCaption)
                            .font(.caption2)
                            .foregroundStyle(WidgetPalette.secondary)
                            .lineLimit(1)
                            .minimumScaleFactor(0.8)
                    }
                }
                Spacer(minLength: 4)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(model.accessibilityLabel)
            ScanButton(isRunning: model.isScanRunning, size: .large, fullWidth: true)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

private struct ScanNowMedium: View {
    let model: ScanNowWidgetModel

    var body: some View {
        HStack(spacing: 18) {
            FreshnessRing(fraction: model.ringFraction, isStale: model.isStale, value: model.ringValue,
                          unit: model.ringUnit + " ago", diameter: 104)
            VStack(alignment: .leading, spacing: 0) {
                VStack(alignment: .leading, spacing: 0) {
                    ScanNowTitle(isStale: model.isStale, title: model.title, font: .footnote,
                                 freshColor: WidgetPalette.secondary)
                    Spacer(minLength: 4)
                    Text("\(model.total) \(WidgetCopy.deviceUnit(model.total))")
                        .font(.system(size: 24, weight: .bold))
                        .monospacedDigit()
                        .foregroundStyle(WidgetPalette.text)
                        .lineLimit(1)
                        .minimumScaleFactor(0.6)
                        .opacity(model.isStale ? 0.6 : 1)
                    Text(model.mediumCaption)
                        .font(.footnote)
                        .foregroundStyle(WidgetPalette.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                        .padding(.top, 3)
                    Spacer(minLength: 4)
                    StatusCapsule(segments: model.segments)
                        .opacity(model.isStale ? 0.6 : 1)
                    Spacer(minLength: 4)
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(model.accessibilityLabel)
                ScanButton(isRunning: model.isScanRunning, size: .large, fullWidth: true)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
    }
}

/// WifiGlyph and the title when fresh; an orange clock and "Out of date" in primary text when stale.
private struct ScanNowTitle: View {
    let isStale: Bool
    let title: String
    let font: Font
    let freshColor: Color

    var body: some View {
        HStack(spacing: isStale ? 6 : 8) {
            if isStale {
                Image(systemName: "clock")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(WidgetPalette.warning)
            } else {
                WidgetMark()
            }
            Text(title)
                .font(isStale ? font.weight(.semibold) : font)
                .foregroundStyle(isStale ? WidgetPalette.text : freshColor)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
        }
    }
}

#Preview("Scan Now small", as: .systemSmall) {
    ScanNowWidget()
} timeline: {
    WidgetSamples.fresh
    WidgetSamples.stale
    WidgetSamples.running
    WidgetSamples.empty
}

#Preview("Scan Now medium", as: .systemMedium) {
    ScanNowWidget()
} timeline: {
    WidgetSamples.fresh
    WidgetSamples.stale
    WidgetSamples.running
    WidgetSamples.empty
}

/// The timeline preview macro takes no modifiers, so the first accessibility size is checked here.
struct ScanNowWidgetAX1Previews: PreviewProvider {
    static var previews: some View {
        Group {
            ScanNowWidgetView(entry: WidgetSamples.stale)
                .previewContext(WidgetPreviewContext(family: .systemSmall))
                .previewDisplayName("Scan Now small AX1")
            ScanNowWidgetView(entry: WidgetSamples.stale)
                .previewContext(WidgetPreviewContext(family: .systemMedium))
                .previewDisplayName("Scan Now medium AX1")
        }
        .environment(\.dynamicTypeSize, .accessibility1)
    }
}
