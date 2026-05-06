// mDNSShark/DesignSystem/CardView.swift
import SwiftUI

struct CardView<Content: View>: View {
    @Environment(\.colorScheme) private var colorScheme
    let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        content
            .padding(16)
            .background(Color(.secondarySystemBackground))
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .shadow(
                color: colorScheme == .light ? .black.opacity(0.06) : .clear,
                radius: 4, x: 0, y: 2
            )
    }
}
