// mDNSShark/App/OnboardingBannerView.swift
import SwiftUI

struct OnboardingBannerView: View {
    @Binding var isVisible: Bool

    var body: some View {
        CardView {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Image(systemName: "info.circle.fill").foregroundColor(AppColors.info)
                    Text("About mDNSShark").font(.subheadline.weight(.semibold))
                    Spacer()
                    Button { withAnimation { isVisible = false } } label: {
                        Image(systemName: "xmark.circle.fill").foregroundColor(.secondary)
                    }
                }
                Text("mDNSShark uses **Bonjour** — Apple's implementation of zero-configuration networking (mDNS + DNS-SD) — to automatically discover devices and services on your local network using industry-standard IP protocols. All scanning and security assessment runs entirely on your device. No data is sent to external servers.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.horizontal)
        .transition(.move(edge: .top).combined(with: .opacity))
    }
}
