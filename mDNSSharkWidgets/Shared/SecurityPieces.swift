import SwiftUI
import WidgetKit
import WidgetSnapshot

extension StatusKind {
    /// The status word shown beside a count where space allows.
    var word: String {
        switch self {
        case .secure: WidgetCopy.secure
        case .warning: WidgetCopy.warning
        case .critical: WidgetCopy.critical
        case .pending: "Pending"
        }
    }
}

/// A status symbol with its literal count; outlined kinds stay outlined in secondary so they never read as a status fill.
struct StatusCountRow: View {
    enum Style {
        /// 22pt symbol, 20pt count and the word under it, for the medium grid.
        case grid
        /// Symbol and count in one line, with the word only when asked, for the large legend and lock screen rows.
        case inline(showsWord: Bool = false, size: CGFloat = 12)
    }

    let segment: CapsuleSegment
    let style: Style
    @Environment(\.widgetRenderingMode) private var mode

    var body: some View {
        switch style {
        case .grid:
            HStack(spacing: 6) {
                symbol.font(.system(size: 22))
                VStack(alignment: .leading, spacing: 1) {
                    Text("\(segment.count)")
                        .font(.system(size: 20, weight: .bold))
                        .monospacedDigit()
                        .foregroundStyle(WidgetPalette.text)
                        .lineLimit(1)
                        .minimumScaleFactor(0.6)
                    // Only a two-word label may wrap, so a single word is never hyphenated.
                    Text(segment.kind.word)
                        .font(.caption2)
                        .foregroundStyle(WidgetPalette.secondary)
                        .lineLimit(segment.kind.word.contains(" ") ? 2 : 1)
                        .minimumScaleFactor(0.7)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        case .inline(let showsWord, let size):
            HStack(spacing: 3) {
                symbol
                Text("\(segment.count)").monospacedDigit().foregroundStyle(WidgetPalette.text)
                if showsWord {
                    Text(segment.kind.word).foregroundStyle(WidgetPalette.secondary)
                }
            }
            .font(.system(size: size, weight: .semibold))
            .lineLimit(1)
        }
    }

    private var symbol: some View {
        Image(systemName: segment.kind.symbol)
            .foregroundStyle(segment.kind.isOutlined ? WidgetPalette.secondary : WidgetPalette.color(for: segment.kind, mode: mode))
    }
}

/// The Security headline: an issue count with its unit on the baseline, or a short title such as All clear.
struct SecurityHeroView: View {
    let hero: SecurityHero
    let size: CGFloat

    var body: some View {
        Group {
            switch hero {
            case .count(let n, let unit):
                HStack(alignment: .firstTextBaseline, spacing: 5) {
                    Text("\(n)")
                        .font(.system(size: size, weight: .bold))
                        .monospacedDigit()
                        .lineLimit(1)
                        .minimumScaleFactor(0.6)
                        .widgetAccentable()
                    Text(unit)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(WidgetPalette.secondary)
                        .lineLimit(1)
                }
            case .title(let title):
                Text(title)
                    .font(.system(size: 34, weight: .bold))
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)
                    .widgetAccentable()
            }
        }
        .foregroundStyle(WidgetPalette.text)
    }
}

/// The caption under the data: an Out of date line when stale, the text, then a checking line while devices are pending.
struct SecurityCaption: View {
    let text: String
    let isStale: Bool
    var checkingNote: String?
    var textLines = 2

    var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            if isStale {
                Text("\(Text(Image(systemName: "clock")).foregroundStyle(WidgetPalette.warning)) \(WidgetCopy.outOfDate)")
            }
            Text(text).lineLimit(textLines)
            if let checkingNote {
                Text("\(Text(Image(systemName: StatusKind.pending.symbol))) \(checkingNote)")
            }
        }
        .font(.caption2)
        .foregroundStyle(WidgetPalette.secondary)
        .lineLimit(1)
        .minimumScaleFactor(0.8)
    }
}

/// A tile with the inner 12pt corners, the shared fill and a hairline stroke.
struct SecurityTile: ViewModifier {
    @Environment(\.colorScheme) private var colorScheme

    func body(content: Content) -> some View {
        content
            .padding(.vertical, 12)
            .padding(.horizontal, 14)
            .background(RoundedRectangle(cornerRadius: 12).fill(WidgetPalette.tileFill(dark: colorScheme == .dark)))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.white.opacity(0.22), lineWidth: 0.5))
    }
}

extension View {
    /// Lock screen shapes draw no background of their own; the system supplies the vibrant material.
    func mdnsAccessoryBackground() -> some View { containerBackground(for: .widget) { Color.clear } }
}
