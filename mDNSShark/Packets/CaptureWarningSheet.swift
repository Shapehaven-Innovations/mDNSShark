// mDNSShark/Packets/CaptureWarningSheet.swift
import SwiftUI

struct CaptureWarningSheet: View {
    let onConfirm: () -> Void
    @Binding var isPresented: Bool

    var body: some View {
        NavigationView {
            VStack(alignment: .leading, spacing: 24) {
                VStack(alignment: .leading, spacing: 12) {
                    Label("Network Activity", systemImage: "exclamationmark.triangle.fill")
                        .font(.headline)
                        .foregroundColor(AppColors.warning)

                    Text("This starts a local capture tunnel on your device, and iOS will ask you to allow a VPN configuration. While capturing, mDNSShark can see the network traffic you send: DNS lookups, destination addresses and ports, and website hostnames. If TLS Inspection is on, it can also see decrypted HTTPS content.\n\nThis data is shown only in this app and saved only on this device, so you can inspect and export your own traffic. Captured traffic is never sent to us or any third party, and is not used for advertising, tracking, or analytics. Your TCP and UDP traffic is forwarded to its destination; ping (ICMP) is not forwarded, and when TLS Inspection is on, QUIC (UDP 443) is blocked so apps fall back to HTTPS. DNS lookups are sent to the resolver set in Settings, which defaults to Google Public DNS (8.8.8.8), so that provider can see them.\n\nYou may notice slower speeds or brief interruptions until you stop capture.")
                        .font(.body)
                        .foregroundColor(.primary)
                }
                .padding()
                .background(Color.secondary.opacity(0.1))
                .cornerRadius(12)

                Spacer()

                VStack(spacing: 12) {
                    Button {
                        isPresented = false
                        onConfirm()
                    } label: {
                        Text("Start Capture")
                            .font(.headline)
                            .frame(maxWidth: .infinity)
                            .padding()
                            .background(AppColors.info)
                            .foregroundColor(.white)
                            .cornerRadius(12)
                    }

                    Button("Cancel") {
                        isPresented = false
                    }
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                }
            }
            .padding()
            .navigationTitle("Before You Start")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}
