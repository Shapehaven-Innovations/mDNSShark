import SwiftUI
import WidgetKit
import WidgetSnapshot

/// The Bluetooth counts a widget draws from its model; hidden from VoiceOver because the parent label speaks the clause.
struct BluetoothLine: View {
    enum Style {
        /// Symbol and the pill text in a filled capsule, with no stroke so it never reads as the Scan button.
        /// Too narrow for the stale age, it shows the count only, then nothing; the spoken clause keeps both.
        case pill
        /// Symbol and the line text, dropping the age, then falling back to the pill.
        case line
        /// The line with "not assessed" after the count, which outlasts the age and "nearby".
        case securityLine
        /// Symbol and nearby count in the lock screen row's inline metrics.
        case inlineCount
    }

    let model: BluetoothIndicatorModel
    let style: Style

    var body: some View {
        content
            .opacity(model.isStale ? 0.6 : 1)
            .accessibilityHidden(true)
    }

    @ViewBuilder private var content: some View {
        switch style {
        case .pill:
            pill
        case .line:
            ViewThatFits(in: .horizontal) {
                text(model.lineText)
                text(model.lineTextWithoutAge)
                pill
            }
        case .securityLine:
            ViewThatFits(in: .horizontal) {
                text(model.securityLineText)
                text(model.securityLineTextWithoutAge)
                text(model.securityLineTextCompact)
                pill
            }
        case .inlineCount:
            HStack(spacing: 3) {
                Image(systemName: WidgetCopy.bluetoothSymbol).foregroundStyle(WidgetPalette.secondary)
                Text("\(model.nearby)").monospacedDigit().foregroundStyle(WidgetPalette.text)
            }
            .font(.system(size: 13, weight: .semibold))
            .lineLimit(1)
        }
    }

    private var pill: some View {
        ViewThatFits(in: .horizontal) {
            capsule(model.pillText)
            if model.pillText != model.pillCountText { capsule(model.pillCountText) }
            EmptyView()
        }
    }

    private func capsule(_ string: String) -> some View {
        HStack(spacing: 3) {
            Image(systemName: WidgetCopy.bluetoothSymbol)
            Text(string).monospacedDigit()
        }
        .font(.caption2.weight(.semibold))
        .foregroundStyle(WidgetPalette.secondary)
        .lineLimit(1)
        .fixedSize()
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(Capsule().fill(WidgetPalette.scanFill))
    }

    /// A stale line swaps the Bluetooth symbol for an orange clock.
    private func text(_ string: String) -> some View {
        HStack(spacing: 4) {
            if model.isStale {
                Image(systemName: "clock").foregroundStyle(WidgetPalette.warning)
            } else {
                Image(systemName: WidgetCopy.bluetoothSymbol).foregroundStyle(WidgetPalette.secondary)
            }
            Text(string).foregroundStyle(WidgetPalette.secondary)
        }
        .font(.caption2)
        .lineLimit(1)
        .minimumScaleFactor(0.8)
    }
}
