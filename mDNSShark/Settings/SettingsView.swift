// mDNSShark/Settings/SettingsView.swift
import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct SettingsView: View {
    // Appearance
    @AppStorage("preferredColorScheme") private var colorSchemeRaw: Int = 0

    // TLS toggle state
    @State private var tlsEnabled: Bool = SharedSettings.tlsInspectionEnabled
    @State private var installedCert: SecCertificate? = KeychainStore.loadCACert()
    @State private var showImportError: String? = nil

    // TLS sheet / warning state
    @State private var showImportPicker = false
    @State private var showPastePEM = false
    @State private var showGenerateCA = false
    @State private var showTLSWarning = false
    @AppStorage("hasSeenTLSWarning") private var hasSeenTLSWarning = false
    @State private var dropCount: Int = SharedSettings.tlsInterceptorDropCount

    // Bypass list
    @State private var bypassList: [String] = SharedSettings.tlsBypassList
    @State private var newBypassDomain = ""

    // DNS
    @State private var dnsPrimary:   String = SharedSettings.dnsPrimary
    @State private var dnsSecondary: String = SharedSettings.dnsSecondary

    // Capture filters
    @State private var activeFilters: Set<String> = SharedSettings.captureFilterProtocols

    var body: some View {
        NavigationView {
            List {
                appearanceSection
                tlsSection
                bypassListSection
                dnsSection
                captureFiltersSection
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.large)
        }
    }

    // MARK: - Appearance

    private var appearanceSection: some View {
        Section("Appearance") {
            Picker("Theme", selection: $colorSchemeRaw) {
                Text("System").tag(0)
                Text("Light").tag(1)
                Text("Dark").tag(2)
            }
            .pickerStyle(.segmented)
        }
    }

    // MARK: - TLS Inspection

    private var tlsSection: some View {
        Section {
            Toggle("Enable TLS Inspection", isOn: Binding(
                get: { tlsEnabled },
                set: { val in
                    if val && !hasSeenTLSWarning {
                        showTLSWarning = true
                    } else {
                        tlsEnabled = val
                        SharedSettings.tlsInspectionEnabled = val
                    }
                }
            ))
            .tint(AppColors.info)

            if let cert = installedCert {
                CertDetailCard(cert: cert).listRowInsets(EdgeInsets())
            } else {
                Text("No certificate installed")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Button("Import from Files…") { showImportPicker = true }
            Button("Paste PEM / P12…")   { showPastePEM = true }
            Button("Generate CA…")       { showGenerateCA = true }

            if installedCert != nil {
                Button("Remove Certificate", role: .destructive) {
                    KeychainStore.deleteCAItems()
                    installedCert = nil
                    tlsEnabled = false
                    SharedSettings.tlsInspectionEnabled = false
                }
            }

            Link("How to configure →",
                 destination: URL(string: "https://github.com/Shapehaven-Innovations/mDNSShark")!)
                .font(.subheadline)

            if dropCount > 0 {
                Text("\(dropCount) connection(s) dropped during TLS inspection")
                    .font(.caption)
                    .foregroundColor(AppColors.warning)
            }
        } header: {
            Text("TLS Inspection")
        } footer: {
            Text("Install a trusted CA certificate on this device before enabling. See the README for steps.")
                .font(.caption)
        }
        .sheet(isPresented: $showImportPicker) { importPickerSheet }
        .sheet(isPresented: $showPastePEM)    { pastePEMSheet }
        .sheet(isPresented: $showGenerateCA)  { generateCASheet }
        .sheet(isPresented: $showTLSWarning)  { tlsWarningSheet }
        .alert("Import Error", isPresented: .constant(showImportError != nil),
               actions: { Button("OK") { showImportError = nil } },
               message: { Text(showImportError ?? "") })
    }

    // MARK: - Sheets

    private var importPickerSheet: some View {
        DocumentPickerView(
            allowedTypes: [UTType.data, UTType.item]
        ) { url in
            do {
                let data = try Data(contentsOf: url)
                try handleImport(data: data, ext: url.pathExtension.lowercased())
            } catch { showImportError = error.localizedDescription }
            showImportPicker = false
        }
    }

    private var pastePEMSheet: some View {
        PastePEMSheet { text, password in
            do { try handlePastedPEM(text: text, password: password) }
            catch { showImportError = error.localizedDescription }
            showPastePEM = false
        }
    }

    private var generateCASheet: some View {
        GenerateCASheet { confirmed in
            showGenerateCA = false
            guard confirmed else { return }
            do { try generateCA() }
            catch { showImportError = error.localizedDescription }
        }
    }

    private var tlsWarningSheet: some View {
        TLSWarningSheet {
            hasSeenTLSWarning = true
            tlsEnabled = true
            SharedSettings.tlsInspectionEnabled = true
            showTLSWarning = false
        } onCancel: {
            showTLSWarning = false
        }
    }

    // MARK: - Import logic

    private func handleImport(data: Data, ext: String, password: String = "") throws {
        if ext == "p12" || ext == "pfx" {
            let opts: [String: Any] = [kSecImportExportPassphrase as String: password]
            var items: CFArray?
            let status = SecPKCS12Import(data as CFData, opts as CFDictionary, &items)
            guard status == errSecSuccess,
                  let arr = items as? [[String: Any]],
                  let first = arr.first else { throw CertError.invalidPEM }
            let id = first[kSecImportItemIdentity as String] as! SecIdentity
            var certRef: SecCertificate?
            var keyRef: SecKey?
            SecIdentityCopyCertificate(id, &certRef)
            SecIdentityCopyPrivateKey(id, &keyRef)
            if let c = certRef { try KeychainStore.saveCACert(c) }
            if let k = keyRef  { try KeychainStore.saveCAKey(k) }
            installedCert = certRef
        } else {
            let certData: Data
            if let pem = String(data: data, encoding: .utf8), pem.contains("-----BEGIN") {
                certData = try decodePEMBlock(pem)
            } else {
                certData = data
            }
            guard let cert = SecCertificateCreateWithData(nil, certData as CFData) else {
                throw CertError.invalidPEM
            }
            try KeychainStore.saveCACert(cert)
            installedCert = cert
        }
    }

    private func handlePastedPEM(text: String, password: String) throws {
        if text.contains("-----BEGIN CERTIFICATE-----") {
            let certDER = try decodePEMBlock(text)
            guard let cert = SecCertificateCreateWithData(nil, certDER as CFData) else {
                throw CertError.invalidPEM
            }
            try KeychainStore.saveCACert(cert)
            installedCert = cert
        }
        if text.contains("PRIVATE KEY") {
            let keyDER = try decodePEMBlock(text)
            let attrs: [String: Any] = [
                kSecAttrKeyType as String:  kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
            ]
            var cfErr: Unmanaged<CFError>?
            guard let key = SecKeyCreateWithData(keyDER as CFData, attrs as CFDictionary, &cfErr) else {
                throw cfErr!.takeRetainedValue() as Error
            }
            try KeychainStore.saveCAKey(key)
        }
    }

    private func decodePEMBlock(_ pem: String) throws -> Data {
        var inside = false
        var base64 = ""
        for line in pem.components(separatedBy: "\n") {
            if line.hasPrefix("-----BEGIN") { inside = true; continue }
            if line.hasPrefix("-----END")   { break }
            if inside { base64 += line.trimmingCharacters(in: .whitespaces) }
        }
        guard !base64.isEmpty,
              let data = Data(base64Encoded: base64, options: .ignoreUnknownCharacters)
        else { throw CertError.invalidPEM }
        return data
    }

    private func generateCA() throws {
        let keyAttrs: [String: Any] = [
            kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]
        var cfErr: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(keyAttrs as CFDictionary, &cfErr) else {
            throw cfErr!.takeRetainedValue() as Error
        }
        let certDER = try X509CertBuilder.buildSelfSignedCA(cn: "mDNSShark CA", privateKey: privateKey)
        guard let cert = SecCertificateCreateWithData(nil, certDER as CFData) else {
            throw CertError.invalidPEM
        }
        try KeychainStore.saveCACert(cert)
        try KeychainStore.saveCAKey(privateKey)
        installedCert = cert
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("mDNSShark-CA.cer")
        try certDER.write(to: url)
        DispatchQueue.main.async {
            guard let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
                  let root = scene.windows.first?.rootViewController else { return }
            let ac = UIActivityViewController(activityItems: [url], applicationActivities: nil)
            root.present(ac, animated: true)
        }
    }

    // MARK: - TLS Bypass List

    private var bypassListSection: some View {
        Section {
            HStack {
                TextField("Add domain (e.g. bank.com)", text: $newBypassDomain)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
                    .onSubmit { addBypassDomain() }
                Button { addBypassDomain() } label: {
                    Image(systemName: "plus.circle.fill")
                        .foregroundColor(AppColors.info)
                }
                .disabled(newBypassDomain.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            ForEach(bypassList, id: \.self) { domain in
                Text(domain).font(.subheadline)
            }
            .onDelete { idxs in
                bypassList.remove(atOffsets: idxs)
                SharedSettings.tlsBypassList = bypassList
            }
        } header: {
            Text("TLS Bypass List")
        } footer: {
            Text("Domains excluded from TLS inspection. Add certificate-pinned apps (banking, health) here.")
                .font(.caption)
        }
    }

    private func addBypassDomain() {
        let domain = newBypassDomain.trimmingCharacters(in: .whitespaces).lowercased()
        guard !domain.isEmpty, !bypassList.contains(domain) else { return }
        bypassList.append(domain)
        SharedSettings.tlsBypassList = bypassList
        newBypassDomain = ""
    }

    // MARK: - DNS Server

    private var dnsSection: some View {
        Section {
            HStack {
                Text("Primary")
                Spacer()
                TextField("8.8.8.8", text: $dnsPrimary)
                    .keyboardType(.numbersAndPunctuation)
                    .multilineTextAlignment(.trailing)
                    .onChange(of: dnsPrimary) { _, newValue in SharedSettings.dnsPrimary = newValue }
            }
            HStack {
                Text("Secondary")
                Spacer()
                TextField("8.8.4.4", text: $dnsSecondary)
                    .keyboardType(.numbersAndPunctuation)
                    .multilineTextAlignment(.trailing)
                    .onChange(of: dnsSecondary) { _, newValue in SharedSettings.dnsSecondary = newValue }
            }
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(dnsSuggestions, id: \.label) { s in
                        Button(s.label) { dnsPrimary = s.value; SharedSettings.dnsPrimary = s.value }
                            .font(.caption)
                            .padding(.horizontal, 10).padding(.vertical, 5)
                            .background(Color(.tertiarySystemBackground))
                            .clipShape(Capsule())
                    }
                }
            }
        } header: {
            Text("DNS Server")
        } footer: {
            Text("Changes take effect on the next tunnel restart.")
                .font(.caption)
        }
    }

    private let dnsSuggestions: [(label: String, value: String)] = [
        ("1.1.1.1 Cloudflare", "1.1.1.1"),
        ("9.9.9.9 Quad9",      "9.9.9.9"),
        ("8.8.8.8 Google",     "8.8.8.8")
    ]

    // MARK: - Capture Filters

    private var captureFiltersSection: some View {
        Section("Capture Filters") {
            ForEach(SharedSettings.allProtocols.sorted(), id: \.self) { proto in
                Toggle(proto, isOn: Binding(
                    get:  { activeFilters.contains(proto) },
                    set:  { on in
                        if on { activeFilters.insert(proto) } else { activeFilters.remove(proto) }
                        SharedSettings.captureFilterProtocols = activeFilters
                    }
                ))
            }
        }
    }
}

// MARK: - Companion sheets

private struct DocumentPickerView: UIViewControllerRepresentable {
    let allowedTypes: [UTType]
    let onPick: (URL) -> Void

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: allowedTypes)
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ vc: UIDocumentPickerViewController, context: Context) {}
    func makeCoordinator() -> Coordinator { Coordinator(onPick: onPick) }

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let onPick: (URL) -> Void
        init(onPick: @escaping (URL) -> Void) { self.onPick = onPick }
        func documentPicker(_ c: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            guard let url = urls.first else { return }
            _ = url.startAccessingSecurityScopedResource()
            onPick(url)
            url.stopAccessingSecurityScopedResource()
        }
    }
}

private struct PastePEMSheet: View {
    @State private var text = ""
    @State private var password = ""
    let onDone: (String, String) -> Void
    var body: some View {
        NavigationView {
            Form {
                Section("PEM / P12 Data") {
                    TextEditor(text: $text)
                        .font(.system(.caption, design: .monospaced))
                        .frame(minHeight: 180)
                }
                Section("Password (P12 only)") {
                    SecureField("Leave blank for PEM", text: $password)
                }
            }
            .navigationTitle("Paste Certificate")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Import") { onDone(text, password) }.disabled(text.isEmpty)
                }
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { onDone("", "") }
                }
            }
        }
    }
}

private struct GenerateCASheet: View {
    let onDone: (Bool) -> Void
    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                Image(systemName: "key.fill")
                    .font(.largeTitle)
                    .foregroundColor(AppColors.info)
                Text("Generate CA Certificate").font(.headline)
                Text("This creates a new Certificate Authority key pair and exports the public certificate for you to install as a trusted root.\n\nSee the README for installation steps.")
                    .font(.body)
                    .multilineTextAlignment(.center)
                    .padding()
                Button("Generate & Export") { onDone(true) }
                    .buttonStyle(.borderedProminent)
                Button("Cancel", role: .cancel) { onDone(false) }
            }
            .padding()
            .navigationTitle("Generate CA")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

private struct TLSWarningSheet: View {
    let onEnable: () -> Void
    let onCancel: () -> Void
    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                Image(systemName: "exclamationmark.shield.fill")
                    .font(.largeTitle)
                    .foregroundColor(AppColors.warning)
                Text("Before enabling TLS Inspection").font(.headline)
                Text("mDNSShark will act as a TLS proxy for all HTTPS traffic.\n\n• Your CA certificate must be installed and trusted in iOS Settings → General → VPN & Device Management.\n• Add certificate-pinned apps (banking, health) to the Bypass List or they will fail.\n• See the README for full setup steps.")
                    .font(.body)
                    .multilineTextAlignment(.center)
                    .padding()
                Button("I understand — Enable", action: onEnable)
                    .buttonStyle(.borderedProminent)
                    .tint(AppColors.warning)
                Button("Cancel", role: .cancel, action: onCancel)
            }
            .padding()
            .navigationTitle("TLS Warning")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}
