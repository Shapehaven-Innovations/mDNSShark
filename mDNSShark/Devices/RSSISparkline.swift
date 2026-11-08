// mDNSShark/Devices/RSSISparkline.swift
import SwiftUI

/// The recent RSSI samples as a polyline. Hidden from VoiceOver; the card speaks the current value.
struct RSSISparkline: View {
    let samples: [Int]

    var body: some View {
        Canvas { context, size in
            guard samples.count >= 2, let lo = samples.min(), let hi = samples.max() else { return }
            let span = CGFloat(max(hi - lo, 1))
            let step = size.width / CGFloat(samples.count - 1)
            var path = Path()
            for (i, value) in samples.enumerated() {
                let point = CGPoint(x: CGFloat(i) * step,
                                    y: size.height - 2 - CGFloat(value - lo) / span * (size.height - 4))
                if i == 0 { path.move(to: point) } else { path.addLine(to: point) }
            }
            context.stroke(path, with: .color(AppColors.info), lineWidth: 1.5)
        }
        .frame(height: 40)
        .accessibilityHidden(true)
    }
}
