import SwiftUI
import UIKit

/// The in-memory Bluetooth advertisement log, newest first, with JSON and CSV export.
struct BLEAdvertisementLogView: View {
    @EnvironmentObject var bluetooth: BluetoothViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var showClearConfirm = false
    @State private var showExportError = false

    private enum Format { case json, csv }

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Text(BLEAdvertisementLogExport.label)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16).padding(.vertical, 8)
                Divider()
                if bluetooth.log.isEmpty {
                    Spacer()
                    VStack(spacing: 12) {
                        Image(systemName: BluetoothSymbol.name).font(.system(size: 48)).foregroundColor(.secondary)
                        Text("No advertisements yet. Scan for Bluetooth devices on the Devices tab.")
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 32)
                    }
                    Spacer()
                } else {
                    List(bluetooth.log.reversed()) { record in
                        row(record)
                    }
                    .listStyle(.plain)
                }
            }
            .navigationTitle("Bluetooth")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Done") { dismiss() }
                }
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    Menu {
                        Section {
                            Button("Export JSON") { export(.json) }
                            Button("Export CSV") { export(.csv) }
                        } header: {
                            Text("Includes names and raw advertisement data of nearby devices.")
                        }
                    } label: {
                        Label("Export", systemImage: "square.and.arrow.up")
                    }
                    .disabled(bluetooth.log.isEmpty)
                    Button(role: .destructive) { showClearConfirm = true } label: {
                        Label("Clear", systemImage: "trash")
                    }
                    .foregroundColor(AppColors.critical)
                    .disabled(bluetooth.log.isEmpty)
                }
            }
            .onAppear { BLEAdvertisementLogExport.purgeStaleExports() }
            .confirmationDialog("Clear Advertisement Log?", isPresented: $showClearConfirm, titleVisibility: .visible) {
                Button("Clear", role: .destructive) { bluetooth.clearLog() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This removes every logged advertisement from memory. Saved devices are kept.")
            }
            .alert("Export Failed", isPresented: $showExportError) {
                Button("OK", role: .cancel) {}
            } message: {
                Text("The export file could not be written.")
            }
        }
    }

    private func row(_ record: BLEAdvertisementRecord) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(Self.timeFormatter.string(from: record.at))
                    .font(.caption.monospacedDigit())
                    .foregroundColor(.secondary)
                Spacer()
                Text("\(record.rssi) dBm")
                    .font(.caption.monospacedDigit())
                    .foregroundColor(.secondary)
            }
            Text(record.name ?? "Unnamed")
                .font(.subheadline.weight(.medium))
                .lineLimit(1)
            if let company = record.companyName {
                Text("Advertised company: \(company)").font(.caption).foregroundColor(.secondary).lineLimit(1)
            }
            if !record.serviceUUIDs.isEmpty {
                Text(record.serviceUUIDs.joined(separator: ", "))
                    .font(.caption2.monospaced())
                    .foregroundColor(.secondary)
                    .lineLimit(2)
            }
        }
        .accessibilityElement(children: .combine)
    }

    /// Writes to the temporary directory only and removes the file once the share sheet finishes.
    private func export(_ format: Format) {
        let records = bluetooth.log
        guard !records.isEmpty else { showExportError = true; return }
        let fm = FileManager.default
        let stem = BLEAdvertisementLogExport.fileStem(now: Date())
        let url: URL
        do {
            switch format {
            case .json:
                url = fm.temporaryDirectory.appendingPathComponent("\(stem).json")
                try? fm.removeItem(at: url)
                try BLEAdvertisementLogExport.json(records).write(to: url, options: BLEAdvertisementLogExport.writeOptions)
            case .csv:
                url = fm.temporaryDirectory.appendingPathComponent("\(stem).csv")
                try? fm.removeItem(at: url)
                try Data(BLEAdvertisementLogExport.csv(records).utf8).write(to: url, options: BLEAdvertisementLogExport.writeOptions)
            }
        } catch {
            showExportError = true
            return
        }

        let ac = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        ac.completionWithItemsHandler = { _, _, _, _ in try? FileManager.default.removeItem(at: url) }
        guard let presenter = Self.topViewController() else {
            try? fm.removeItem(at: url)
            return
        }
        ac.popoverPresentationController?.sourceView = presenter.view
        presenter.present(ac, animated: true)
    }

    /// This view is itself a sheet, so the share sheet has to go on the topmost presented controller.
    private static func topViewController() -> UIViewController? {
        let scene = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.first
        var top = scene?.windows.first(where: \.isKeyWindow)?.rootViewController ?? scene?.windows.first?.rootViewController
        while let presented = top?.presentedViewController { top = presented }
        return top
    }
}
