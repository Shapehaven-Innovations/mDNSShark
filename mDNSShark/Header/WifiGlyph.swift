// mDNSShark/Header/WifiGlyph.swift
import SwiftUI

/// Wifi signal with rounded ends and no background, matching the app icon. Fills with the surrounding foreground style and scales to its frame.
struct WifiGlyph: View {
    var body: some View {
        WifiShape()
            .aspectRatio(1, contentMode: .fit)
            .accessibilityHidden(true)
    }
}

/// Three round-capped arcs fanning up from a dot, laid out in stroke-width units so the gaps stay legible at 14pt.
private struct WifiShape: Shape {
    private static let gap = 0.8
    private static let dotRadius = 0.78
    private static let radii = [dotRadius + gap + 0.5, dotRadius + 2 * gap + 2.5, dotRadius + 3 * gap + 4.5]
    private static let designHeight = radii[2] + 0.5 + dotRadius
    private static let designWidth = 2 * (radii[2] * sin(.pi / 4) + 0.5)

    func path(in rect: CGRect) -> Path {
        let unit = min(rect.width, rect.height) / Self.designWidth
        let center = CGPoint(x: rect.midX,
                             y: rect.midY - Self.designHeight * unit / 2 + (Self.radii[2] + 0.5) * unit)
        var arcs = Path()
        for radius in Self.radii {
            arcs.move(to: CGPoint(x: center.x + radius * unit * cos(-.pi * 0.75),
                                  y: center.y + radius * unit * sin(-.pi * 0.75)))
            arcs.addArc(center: center, radius: radius * unit,
                        startAngle: .degrees(-135), endAngle: .degrees(-45), clockwise: false)
        }
        var path = arcs.strokedPath(StrokeStyle(lineWidth: unit, lineCap: .round))
        let dot = Self.dotRadius * unit
        path.addEllipse(in: CGRect(x: center.x - dot, y: center.y - dot, width: 2 * dot, height: 2 * dot))
        return path
    }
}
