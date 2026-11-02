import SwiftUI
import WidgetKit
import WidgetSnapshot

/// Widget A: the device count from the last scan, its status capsule, a Scan button and, when medium, a ranked bar per device type.
struct DevicesWidget: Widget {
    let kind = WidgetKind.devices

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: kind, provider: SnapshotTimelineProvider()) { entry in
            DevicesWidgetView(entry: entry)
        }
        .configurationDisplayName("Devices Online")
        .description("Devices found by your last scan, with a Scan button.")
        .supportedFamilies([.systemSmall, .systemMedium])
    }
}

struct DevicesWidgetView: View {
    let entry: SnapshotEntry
    @Environment(\.widgetFamily) private var family

    var body: some View {
        content
            .mdnsWidgetBackground()
            .widgetURL(WidgetLink.devicesTab)
            .dynamicTypeSize(...DynamicTypeSize.accessibility1)
    }

    @ViewBuilder private var content: some View {
        switch DevicesWidgetModel.make(entry.result, now: entry.date, isScanRunning: entry.isScanRunning) {
        case .noScan: NoScanView(showsScan: true, isRunning: entry.isScanRunning)
        case .needsUpdate: NeedsUpdateView()
        case .loaded(let model):
            if family == .systemMedium { DevicesMedium(model: model) } else { DevicesSmall(model: model) }
        }
    }
}

private struct DevicesSmall: View {
    let model: DevicesWidgetModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                WidgetMark()
                Spacer(minLength: 4)
                ScanButton(isRunning: model.isScanRunning, size: .compact)
            }
            Spacer(minLength: 4)
            DevicesSummary(model: model, heroSize: 44)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

private struct DevicesMedium: View {
    let model: DevicesWidgetModel

    var body: some View {
        HStack(alignment: .top, spacing: 18) {
            VStack(alignment: .leading, spacing: 0) {
                WidgetMark()
                Spacer(minLength: 2)
                DevicesSummary(model: model, heroSize: 36, capsuleTop: 6, label: model.mediumAccessibilityLabel)
                ScanButton(isRunning: model.isScanRunning, size: .large)
                    .fixedSize()
                    .padding(.top, 6)
            }
            .frame(width: 142, alignment: .leading)
            .frame(maxHeight: .infinity)

            TypeChart(types: model.types, isStale: model.isStale)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
    }
}

/// Hero count, capsule and age caption as one VoiceOver element; the Scan button stays outside it.
private struct DevicesSummary: View {
    let model: DevicesWidgetModel
    let heroSize: CGFloat
    var capsuleTop: CGFloat = 12
    var label: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Group {
                HStack(alignment: .firstTextBaseline, spacing: 5) {
                    Text("\(model.total)")
                        .font(.system(size: heroSize, weight: .bold))
                        .monospacedDigit()
                        .lineLimit(1)
                        .minimumScaleFactor(0.6)
                        .widgetAccentable()
                    Text(model.unit)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(WidgetPalette.secondary)
                        .lineLimit(1)
                }
                .foregroundStyle(WidgetPalette.text)
                StatusCapsule(segments: model.segments)
                    .padding(.top, capsuleTop)
            }
            .opacity(model.isStale ? 0.6 : 1)
            Spacer(minLength: 4)
            caption
                .font(.caption2)
                .foregroundStyle(WidgetPalette.secondary)
                .lineLimit(2)
                .minimumScaleFactor(0.8)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label ?? model.accessibilityLabel)
    }

    private var caption: Text {
        guard model.isStale else { return Text(model.ageText) }
        let clock = Text(Image(systemName: "clock")).foregroundStyle(WidgetPalette.warning)
        return Text("\(clock) \(WidgetCopy.outOfDate)\n\(model.ageText)")
    }
}

#Preview("Devices small", as: .systemSmall) {
    DevicesWidget()
} timeline: {
    WidgetSamples.fresh
    WidgetSamples.stale
    WidgetSamples.running
    WidgetSamples.empty
}

#Preview("Devices medium", as: .systemMedium) {
    DevicesWidget()
} timeline: {
    WidgetSamples.fresh
    WidgetSamples.tenTypes
    WidgetSamples.fourteenTypes
    WidgetSamples.staleFourteenTypes
    WidgetSamples.running
    WidgetSamples.empty
}

/// The timeline preview macro takes no modifiers, so the first accessibility size is checked here.
struct DevicesWidgetAX1Previews: PreviewProvider {
    static var previews: some View {
        Group {
            DevicesWidgetView(entry: WidgetSamples.stale)
                .previewContext(WidgetPreviewContext(family: .systemSmall))
                .previewDisplayName("Devices small AX1")
            DevicesWidgetView(entry: WidgetSamples.staleFourteenTypes)
                .previewContext(WidgetPreviewContext(family: .systemMedium))
                .previewDisplayName("Devices medium AX1")
        }
        .environment(\.dynamicTypeSize, .accessibility1)
    }
}
