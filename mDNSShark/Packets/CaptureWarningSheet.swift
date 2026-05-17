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

                    Text("Capturing packets requires routing all network traffic through this app. You may notice slower speeds or brief interruptions during the session. This is normal and resolves when you stop capture.")
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
