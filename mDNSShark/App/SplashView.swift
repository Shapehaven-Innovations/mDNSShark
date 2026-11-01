// mDNSShark/App/SplashView.swift
import SwiftUI

/// Animated hand-off from the static launch storyboard: the wifi glyph springs in, sonar rings ripple out, the name rises in, then the whole view fades away. Tap to skip.
struct SplashView: View {
    /// Called once the splash has fully faded; ContentView starts the Local Network check from here, so the system alert never overlaps the splash.
    let onFinished: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.colorScheme) private var scheme
    @State private var glyphShown = false
    @State private var titleShown = false
    @State private var leaving = false

    // Sampled from the app icon so the splash reads as the icon coming to life.
    private static let glyphTop = Color(red: 0.98, green: 0.98, blue: 0.98)
    private static let glyphBottom = Color(red: 0.74, green: 0.74, blue: 0.76)

    private var iconGradient: LinearGradient {
        let colors = scheme == .dark
            ? [Color(red: 0.08, green: 0.32, blue: 0.36), Color(red: 0.0, green: 0.09, blue: 0.12)]
            : [Color(red: 0.14, green: 0.42, blue: 0.47), Color(red: 0.01, green: 0.18, blue: 0.21)]
        return LinearGradient(colors: colors, startPoint: .top, endPoint: .bottom)
    }

    var body: some View {
        ZStack {
            // Flat base matches the launch storyboard; the icon gradient fades in over it.
            Color("SplashBackground").ignoresSafeArea()
            iconGradient.ignoresSafeArea()
                .opacity(glyphShown ? 1 : 0)
                .animation(.easeOut(duration: 0.5), value: glyphShown)

            ZStack {
                if !reduceMotion {
                    ForEach(0..<3, id: \.self) { i in
                        SonarRing(color: .white.opacity(0.4), delay: 0.25 + Double(i) * 0.2)
                    }
                }
                WifiGlyph()
                    .foregroundStyle(LinearGradient(colors: [Self.glyphTop, Self.glyphBottom], startPoint: .top, endPoint: .bottom))
                    .shadow(color: .black.opacity(0.35), radius: 1, x: 0, y: 3)
                    .frame(width: 96, height: 96)
                    .scaleEffect(glyphShown || reduceMotion ? 1 : 0.4)
                    .opacity(glyphShown ? 1 : 0)
            }
            .offset(y: -24)

            VStack(spacing: 4) {
                Text("mDNSShark").font(.title2.weight(.bold)).fontDesign(.rounded).foregroundStyle(.white)
                Text("Network Security Scanner").font(.footnote).foregroundStyle(.white.opacity(0.7))
            }
            .dynamicTypeSize(...DynamicTypeSize.xxxLarge) // Decorative and hidden from VoiceOver, so cap it to keep clear of the glyph.
            .offset(y: 70 + (titleShown || reduceMotion ? 0 : 14))
            .opacity(titleShown ? 1 : 0)
        }
        .opacity(leaving ? 0 : 1)
        .scaleEffect(leaving && !reduceMotion ? 1.06 : 1)
        .accessibilityHidden(true)
        .contentShape(Rectangle())
        .onTapGesture { finish() }
        .task { await run() }
    }

    private func finish() {
        guard !leaving else { return }
        // Fade the title first so it is never on screen together with the header's copy of it.
        withAnimation(.easeIn(duration: 0.15)) { titleShown = false }
        // The completion fires when the fade has really finished, so the overlay never vanishes while still partly visible.
        withAnimation(.easeIn(duration: reduceMotion ? 0.2 : 0.35), completionCriteria: .removed) {
            leaving = true
        } completion: {
            onFinished()
        }
    }

    private func run() async {
        // The short sleep lets the first frame commit so the entrance animates instead of rendering its end state. Each step stops if a tap already started the exit.
        try? await Task.sleep(for: .milliseconds(30))
        guard !leaving, !Task.isCancelled else { return }
        if reduceMotion {
            withAnimation(.easeOut(duration: 0.25)) { glyphShown = true; titleShown = true }
            try? await Task.sleep(for: .milliseconds(500))
        } else {
            withAnimation(.spring(response: 0.6, dampingFraction: 0.6)) { glyphShown = true }
            try? await Task.sleep(for: .milliseconds(250))
            guard !leaving, !Task.isCancelled else { return }
            withAnimation(.easeOut(duration: 0.5)) { titleShown = true }
            try? await Task.sleep(for: .milliseconds(800))
        }
        guard !Task.isCancelled else { return }
        finish()
    }
}

/// One expanding ring. It stays invisible until its delay passes, so nothing shows before the glyph lands.
private struct SonarRing: View {
    let color: Color
    let delay: Double
    @State private var opacity = 0.0
    @State private var scale = 0.6

    var body: some View {
        Circle()
            .stroke(color, lineWidth: 2)
            .frame(width: 96, height: 96)
            .scaleEffect(scale)
            .opacity(opacity)
            .task {
                try? await Task.sleep(for: .seconds(delay))
                opacity = 0.9
                try? await Task.sleep(for: .milliseconds(50))
                withAnimation(.easeOut(duration: 1.4)) { scale = 3.2; opacity = 0 }
            }
    }
}
