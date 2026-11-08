import SwiftUI
import WidgetKit
import WidgetSnapshot

/// Security at a Glance: issues from the last scan with not probed always stated, in three home screen sizes and three lock screen shapes.
struct SecurityWidget: Widget {
    let kind = WidgetKind.security

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: kind, provider: SnapshotTimelineProvider()) { entry in
            SecurityWidgetView(entry: entry)
        }
        .configurationDisplayName("Security at a Glance")
        .description("Issues found by your last scan, including devices not probed.")
        .supportedFamilies([.systemSmall, .systemMedium, .systemLarge,
                            .accessoryCircular, .accessoryRectangular, .accessoryInline])
    }
}

struct SecurityWidgetView: View {
    let entry: SnapshotEntry
    @Environment(\.widgetFamily) private var family

    var body: some View {
        Group {
            switch family {
            case .accessoryCircular, .accessoryRectangular, .accessoryInline:
                accessory.mdnsAccessoryBackground()
            default:
                home.mdnsWidgetBackground()
            }
        }
        .widgetURL(WidgetLink.securityTab)
        .dynamicTypeSize(...DynamicTypeSize.accessibility1)
    }

    @ViewBuilder private var home: some View {
        switch SecurityWidgetModel.make(entry.result, now: entry.date, isScanRunning: entry.isScanRunning) {
        case .noScan: NoScanView(showsScan: family == .systemLarge, isRunning: entry.isScanRunning)
        case .needsUpdate: NeedsUpdateView()
        case .loaded(let model):
            switch family {
            case .systemMedium: SecurityMedium(model: model)
            case .systemLarge: SecurityLarge(model: model)
            default: SecuritySmall(model: model)
            }
        }
    }

    @ViewBuilder private var accessory: some View {
        switch SecurityAccessoryModel.make(entry.result, now: entry.date, isScanRunning: entry.isScanRunning) {
        case .noScan:
            AccessoryNotice(symbol: StatusKind.notProbed.symbol, text: WidgetCopy.noScan, label: WidgetCopy.emptyAccessibilityLabel)
        case .needsUpdate:
            AccessoryNotice(symbol: "arrow.down.app", text: WidgetCopy.updateApp, label: WidgetCopy.needsUpdateAccessibilityLabel)
        case .loaded(let model):
            switch family {
            case .accessoryCircular: SecurityCircular(model: model)
            case .accessoryRectangular: SecurityRectangular(model: model)
            default: Label(model.inlineText, systemImage: model.inlineSymbol).accessibilityLabel(model.accessibilityLabel)
            }
        }
    }
}

/// The Security title with the app mark, and an optional trailing view.
private struct SecurityHeader<Trailing: View>: View {
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack(spacing: 8) {
            WidgetMark()
            Text(WidgetCopy.security)
                .font(.footnote.weight(.semibold))
                .foregroundStyle(WidgetPalette.text)
                .lineLimit(1)
                .minimumScaleFactor(0.6)
            Spacer(minLength: 4)
            trailing
        }
    }
}

/// The small header's state symbol: filled in status color, or outlined in secondary for not probed and pending.
private struct HeaderSymbol: View {
    let kind: StatusKind?
    @Environment(\.widgetRenderingMode) private var mode

    var body: some View {
        if let kind {
            Image(systemName: kind.symbol)
                .font(.system(size: 24))
                .foregroundStyle(kind.isOutlined ? WidgetPalette.secondary : WidgetPalette.color(for: kind, mode: mode))
        }
    }
}

private struct SecuritySmall: View {
    let model: SecurityWidgetModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SecurityHeader {
                HStack(spacing: 6) {
                    if let bluetooth = model.bluetooth { BluetoothLine(model: bluetooth, style: .pill) }
                    HeaderSymbol(kind: model.headerSymbol)
                }
            }
            Spacer(minLength: 4)
            Group {
                SecurityHeroView(hero: model.hero, size: 44)
                StatusCapsule(segments: model.segments).padding(.top, 12)
            }
            .opacity(model.isStale ? 0.6 : 1)
            Spacer(minLength: 4)
            SecurityCaption(text: model.smallCaption, isStale: model.isStale, checkingNote: model.checkingNote, textLines: 1)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        // A small widget has no room for accessibility sizes under a 44pt hero, so its text stops at xLarge.
        .dynamicTypeSize(...DynamicTypeSize.xLarge)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(model.accessibilityLabel)
    }
}

private struct SecurityMedium: View {
    let model: SecurityWidgetModel

    var body: some View {
        HStack(alignment: .center, spacing: 18) {
            VStack(alignment: .leading, spacing: 0) {
                SecurityHeader { EmptyView() }
                Spacer(minLength: 4)
                SecurityHeroView(hero: model.hero, size: 52).opacity(model.isStale ? 0.6 : 1)
                Spacer(minLength: 4)
                if let bluetooth = model.bluetooth {
                    BluetoothLine(model: bluetooth, style: .securityLine).padding(.bottom, 3)
                }
                SecurityCaption(text: model.ageText, isStale: model.isStale, checkingNote: model.checkingNote)
            }
            .frame(width: 130, alignment: .leading)
            .frame(maxHeight: .infinity)

            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 10) {
                ForEach(0..<(model.grid.count + 1) / 2, id: \.self) { row in
                    GridRow {
                        ForEach(model.grid.indices.filter { $0 / 2 == row }, id: \.self) { i in
                            StatusCountRow(segment: model.grid[i], style: .grid)
                        }
                    }
                }
            }
            .opacity(model.isStale ? 0.6 : 1)
            // Four labeled counts fill the right half, so their text stops growing at xLarge.
            .dynamicTypeSize(...DynamicTypeSize.xLarge)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(model.accessibilityLabel)
    }
}

private struct SecurityLarge: View {
    let model: SecurityWidgetModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            SecurityHeader { ScanButton(isRunning: model.isScanRunning, size: .compact) }
            VStack(alignment: .leading, spacing: 0) {
                Spacer(minLength: 2)
                Group {
                    // A title hero or a pending item can leave no room beside the hero, so the legend then drops below it.
                    ViewThatFits(in: .horizontal) {
                        HStack(alignment: .bottom) {
                            SecurityHeroView(hero: model.hero, size: 52).fixedSize()
                            Spacer(minLength: 8)
                            legend.padding(.bottom, 6)
                        }
                        VStack(alignment: .leading, spacing: 4) {
                            SecurityHeroView(hero: model.hero, size: 52)
                            legend
                        }
                    }
                    StatusCapsule(segments: model.segments).padding(.top, 10)
                }
                .opacity(model.isStale ? 0.6 : 1)
                Spacer(minLength: 6)
                IssueChartView(chart: model.chart, isStale: model.isStale).modifier(SecurityTile())
                if let bluetooth = model.bluetooth {
                    BluetoothLine(model: bluetooth, style: .securityLine).padding(.top, 6)
                }
                Spacer(minLength: 4)
                // Pending already shows in the large legend, so the caption carries no checking line.
                SecurityCaption(text: model.largeCaption, isStale: model.isStale)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(model.largeAccessibilityLabel)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private var legend: some View {
        HStack(spacing: 10) {
            ForEach(model.legend, id: \.kind) { StatusCountRow(segment: $0, style: .inline()) }
        }
        .fixedSize()
    }
}

private struct SecurityCircular: View {
    let model: SecurityAccessoryModel

    var body: some View {
        Gauge(value: model.gaugeFraction) {
            Image(systemName: model.stateSymbol)
        } currentValueLabel: {
            Text("\(model.gaugeValue)").monospacedDigit()
        }
        .gaugeStyle(.accessoryCircular)
        .opacity(model.isStale ? 0.6 : 1)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(model.accessibilityLabel)
    }
}

private struct SecurityRectangular: View {
    let model: SecurityAccessoryModel

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            HStack(spacing: 5) {
                if model.isStale {
                    Image(systemName: "clock")
                } else {
                    WifiGlyph().frame(width: 14, height: 11)
                }
                Text(model.rectTitle).lineLimit(1).minimumScaleFactor(0.6)
            }
            .font(.headline)
            .widgetAccentable()
            row(model.primaryRow)
            row(model.secondaryRow, bluetooth: model.bluetooth).opacity(0.85)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(model.accessibilityLabel)
    }

    /// Words drop first when the row is too wide; the counts always stay, and a Bluetooth count is dropped last.
    private func row(_ segments: [CapsuleSegment], bluetooth: BluetoothIndicatorModel? = nil) -> some View {
        ViewThatFits(in: .horizontal) {
            rowContent(segments, words: true, bluetooth: bluetooth)
            rowContent(segments, words: false, bluetooth: bluetooth)
            rowContent(segments, words: false, bluetooth: nil)
        }
    }

    private func rowContent(_ segments: [CapsuleSegment], words: Bool, bluetooth: BluetoothIndicatorModel?) -> some View {
        HStack(spacing: 10) {
            ForEach(segments, id: \.kind) { StatusCountRow(segment: $0, style: .inline(showsWord: words, size: 13)) }
            if let bluetooth { BluetoothLine(model: bluetooth, style: .inlineCount) }
        }
    }
}

/// No scan and needs update on the lock screen: one symbol and one short line.
private struct AccessoryNotice: View {
    let symbol: String
    let text: String
    let label: String
    @Environment(\.widgetFamily) private var family

    var body: some View {
        Group {
            switch family {
            case .accessoryInline:
                Label(text, systemImage: symbol)
            case .accessoryCircular:
                ZStack {
                    AccessoryWidgetBackground()
                    VStack(spacing: 1) {
                        Image(systemName: symbol).font(.system(size: 18))
                        Text(text).font(.system(size: 9, weight: .semibold)).multilineTextAlignment(.center)
                            .lineLimit(2).minimumScaleFactor(0.8)
                    }
                    .padding(6)
                }
            default:
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 5) {
                        WifiGlyph().frame(width: 14, height: 11)
                        Text(WidgetCopy.security)
                    }
                    .font(.headline)
                    .widgetAccentable()
                    Label(text, systemImage: symbol).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
    }
}

#Preview("Security small", as: .systemSmall) {
    SecurityWidget()
} timeline: {
    WidgetSamples.securityIssues
    WidgetSamples.securityBluetooth
    WidgetSamples.securityAllClear
    WidgetSamples.securityChecking
    WidgetSamples.securityNotProbed
    WidgetSamples.securityStale
    WidgetSamples.securityNoDevices
    WidgetSamples.empty
    WidgetSamples.needsUpdate
}

#Preview("Security medium", as: .systemMedium) {
    SecurityWidget()
} timeline: {
    WidgetSamples.securityIssues
    WidgetSamples.securityBluetooth
    WidgetSamples.securityAllClear
    WidgetSamples.securityChecking
    WidgetSamples.securityNotProbed
    WidgetSamples.securityStale
    WidgetSamples.securityNoDevices
    WidgetSamples.empty
    WidgetSamples.needsUpdate
}

#Preview("Security large", as: .systemLarge) {
    SecurityWidget()
} timeline: {
    WidgetSamples.securityIssues
    WidgetSamples.securityBluetooth
    WidgetSamples.securityAllClear
    WidgetSamples.securityChecking
    WidgetSamples.securityNotProbed
    WidgetSamples.securityStale
    WidgetSamples.securityNoDevices
    WidgetSamples.securityFew
    WidgetSamples.securityBusy
    WidgetSamples.securityRunning
    WidgetSamples.empty
    WidgetSamples.needsUpdate
}

#Preview("Security circular", as: .accessoryCircular) {
    SecurityWidget()
} timeline: {
    WidgetSamples.securityIssues
    WidgetSamples.securityBluetooth
    WidgetSamples.securityAllClear
    WidgetSamples.securityStale
    WidgetSamples.empty
    WidgetSamples.needsUpdate
}

#Preview("Security rectangular", as: .accessoryRectangular) {
    SecurityWidget()
} timeline: {
    WidgetSamples.securityIssues
    WidgetSamples.securityBluetooth
    WidgetSamples.securityAllClear
    WidgetSamples.securityStale
    WidgetSamples.empty
    WidgetSamples.needsUpdate
}

#Preview("Security inline", as: .accessoryInline) {
    SecurityWidget()
} timeline: {
    WidgetSamples.securityIssues
    WidgetSamples.securityBluetooth
    WidgetSamples.securityAllClear
    WidgetSamples.securityStale
    WidgetSamples.empty
    WidgetSamples.needsUpdate
}

/// The timeline preview macro takes no modifiers, so the first accessibility size and the accented mode are checked here.
struct SecurityWidgetAX1Previews: PreviewProvider {
    static var previews: some View {
        Group {
            SecurityWidgetView(entry: WidgetSamples.securityStale)
                .previewContext(WidgetPreviewContext(family: .systemSmall))
                .previewDisplayName("Security small AX1")
            SecurityWidgetView(entry: WidgetSamples.securityStale)
                .previewContext(WidgetPreviewContext(family: .systemMedium))
                .previewDisplayName("Security medium AX1")
            SecurityWidgetView(entry: WidgetSamples.securityStale)
                .previewContext(WidgetPreviewContext(family: .systemLarge))
                .previewDisplayName("Security large AX1")
            SecurityWidgetView(entry: WidgetSamples.securityBluetooth)
                .previewContext(WidgetPreviewContext(family: .systemSmall))
                .previewDisplayName("Security small Bluetooth AX1")
            SecurityWidgetView(entry: WidgetSamples.securityBluetooth)
                .previewContext(WidgetPreviewContext(family: .systemMedium))
                .previewDisplayName("Security medium Bluetooth AX1")
            SecurityWidgetView(entry: WidgetSamples.securityBluetooth)
                .previewContext(WidgetPreviewContext(family: .systemLarge))
                .previewDisplayName("Security large Bluetooth AX1")
            ForEach(Array([("stale Bluetooth", WidgetSamples.securityStaleBluetooth), ("both stale", WidgetSamples.securityBothStaleBluetooth)].enumerated()), id: \.offset) { _, item in
                SecurityWidgetView(entry: item.1)
                    .previewContext(WidgetPreviewContext(family: .systemSmall))
                    .previewDisplayName("Security small \(item.0) AX1")
                SecurityWidgetView(entry: item.1)
                    .previewContext(WidgetPreviewContext(family: .systemMedium))
                    .previewDisplayName("Security medium \(item.0) AX1")
                SecurityWidgetView(entry: item.1)
                    .previewContext(WidgetPreviewContext(family: .systemLarge))
                    .previewDisplayName("Security large \(item.0) AX1")
            }
        }
        .environment(\.dynamicTypeSize, .accessibility1)
    }
}
