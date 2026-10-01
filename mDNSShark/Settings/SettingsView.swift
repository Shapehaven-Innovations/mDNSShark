// mDNSShark/Settings/SettingsView.swift
import SwiftUI
import UniformTypeIdentifiers
import UIKit
import StoreKit

struct SettingsView: View {
    @StateObject private var purchase = PurchaseManager.shared
    @State private var showManageSubscriptions = false

    // Appearance
    @AppStorage("preferredColorScheme") private var colorSchemeRaw: Int = 0

    // TLS toggle state
    @State private var tlsEnabled: Bool = SharedSettings.tlsInspectionEnabled
    @State private var installedCert: SecCertificate? = KeychainStore.loadCACert()
    @State private var showImportError: String? = nil

    // TLS sheet / warning state
    // A single item-driven sheet instead of four chained .sheet(isPresented:) modifiers
    // on the same view: that pattern flashes and auto-dismisses the first presentation
    // on iOS (SwiftUI only reliably tracks one presentation per view identity).
    @State private var activeSheet: TLSSheet?
    @AppStorage("hasSeenTLSWarning") private var hasSeenTLSWarning = false
    @State private var purchaseInFlight = false
    // dropCount/lastDropReason UI disabled 2026-09-26 — see todo.md item 7's
    // "Last: line" note for why (SharedSettings.tlsInterceptorDropCount has
    // no reset path anywhere, so once any session ever drops, this text
    // never goes away again for the life of the install). Left commented
    // rather than deleted: the underlying SharedSettings counters and the
    // TLSInterceptor/PacketForwarder writers that feed them are still real
    // diagnostics and may get a proper reset-on-relevant-event treatment
    // later instead of just being cut.
    // @State private var dropCount: Int = SharedSettings.tlsInterceptorDropCount
    // @State private var lastDropReason: String = SharedSettings.tlsInterceptorLastError

    // Bypass list
    @State private var bypassList: [String] = SharedSettings.tlsBypassList
    @State private var newBypassDomain = ""

    // DNS
    @State private var dnsPrimary:   String = SharedSettings.dnsPrimary
    @State private var dnsSecondary: String = SharedSettings.dnsSecondary

    // Capture filters
    @State private var activeFilters: Set<String> = SharedSettings.captureFilterProtocols
    @State private var includeAllNetworks: Bool = SharedSettings.includeAllNetworksInCapture

    var body: some View {
        NavigationView {
            List {
                appearanceSection
                tlsSection
                bypassListSection
                dnsSection
                captureFiltersSection
                captureRoutingSection
                aboutSection
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.large)
            // .onAppear dropCount/lastDropReason refresh disabled alongside
            // the "Last:" UI block above (see the @State comment near the
            // top of this file).
            // .onAppear {
            //     dropCount = SharedSettings.tlsInterceptorDropCount
            //     lastDropReason = SharedSettings.tlsInterceptorLastError
            // }
            // Presentation modifiers (.sheet/.alert) must live on the List, not on a
            // Section inside it: List's row machinery (_VariadicView) enumerates a
            // Section's children and reapplies ambient modifiers to each one, so a
            // .sheet attached to a Section opens one PresentationHostingController per
            // row simultaneously. Only the first succeeds; the rest fail with "already
            // presenting" and SwiftUI's recovery resets the bound item back to nil,
            // which reads as the sheet flashing up then immediately back down.
            .sheet(item: $activeSheet) { sheet in
                switch sheet {
                case .importPicker: importPickerSheet
                case .pastePEM:     pastePEMSheet
                case .generateCA:   generateCASheet
                case .tlsWarning:   tlsWarningSheet
                }
            }
            .manageSubscriptionsSheet(isPresented: $showManageSubscriptions)
            .onAppear { purchase.lastError = nil }
            .alert("Import Error", isPresented: Binding(
                get: { showImportError != nil },
                set: { if !$0 { showImportError = nil } }
            ), actions: { Button("OK") { showImportError = nil } },
               message: { Text(showImportError ?? "") })
            .alert("Store Error", isPresented: Binding(
                get: { purchase.lastError != nil },
                set: { if !$0 { purchase.lastError = nil } }
            ), actions: { Button("OK") { purchase.lastError = nil } },
               message: { Text(purchase.lastError ?? "") })
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
            if purchase.hasAccess {
                Toggle("Enable TLS Inspection", isOn: Binding(
                    get: { tlsEnabled },
                    set: { val in
                        if val && !hasSeenTLSWarning {
                            activeSheet = .tlsWarning
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

                Button("Import from Files…") { activeSheet = .importPicker }
                Button("Paste PEM / P12…")   { activeSheet = .pastePEM }
                Button("Generate CA…")       { activeSheet = .generateCA }

                if installedCert != nil {
                    Button("Remove Certificate", role: .destructive) {
                        KeychainStore.deleteCAItems()
                        installedCert = nil
                        tlsEnabled = false
                        SharedSettings.tlsInspectionEnabled = false
                    }
                }

                subscriptionStatusRows
                restoreButton

                // "N connection(s) dropped" / "Last: ..." UI disabled
                // 2026-09-26 (todo.md item 7): tlsInterceptorDropCount never
                // resets, so this text never goes away once any session has
                // ever dropped, across every future launch until reinstall.
                // if dropCount > 0 {
                //     Text("\(dropCount) connection(s) dropped during TLS inspection")
                //         .font(.caption)
                //         .foregroundColor(AppColors.warning)
                //     if !lastDropReason.isEmpty {
                //         Text("Last: \(lastDropReason)")
                //             .font(.caption2)
                //             .foregroundColor(.secondary)
                //     }
                // }
            } else {
                tlsGateView
            }

            Link("How to configure →",
                 destination: URL(string: "https://github.com/Shapehaven-Innovations/mDNSShark")!)
                .font(.subheadline)
        } header: {
            Text("TLS Inspection")
        } footer: {
            Text("Install a trusted CA certificate on this device before enabling. See the README for steps. The TLS Inspection toggle only controls whether HTTPS traffic is MITM-proxied for decryption; packet capture runs regardless, recording either decrypted or still-encrypted payloads.")
                .font(.caption)
        }
    }

    @ViewBuilder
    private var tlsGateView: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("TLS Inspection decrypts HTTPS traffic on this device so you can see what your apps are actually sending.")
                .font(.subheadline)
                .foregroundColor(.secondary)

            Button(subscribeLabel) { run { await purchase.subscribe() } }
                .buttonStyle(.borderedProminent)
                .disabled(purchaseInFlight)
            Text(subscriptionDisclosure)
                .font(.caption)
                .foregroundColor(.secondary)
            // Billing retry drops the entitlement, so the payment-issue hint and Manage
            // button must also be reachable from the gate.
            subscriptionStatusRows
            restoreButton
            legalLinks
        }
        .padding(.vertical, 4)
    }

    private var subscribeLabel: String {
        if purchase.trialLengthText != nil, purchase.trialEligible { return "Start Free Trial" }
        return purchase.monthlyPrice.map { "Subscribe for \($0)/month" } ?? "Subscribe"
    }

    // Guideline 3.1.2: name, length, price, trial terms, auto-renewal and how to cancel.
    private var subscriptionDisclosure: String {
        guard let price = purchase.monthlyPrice else {
            return "TLS Inspection Monthly is an auto-renewing monthly subscription. The price is shown once the App Store responds."
        }
        let renewal = "\(price) per month, renewing automatically until cancelled."
        let cancel = "Cancel anytime in Settings > Apple Account > Subscriptions."
        if let trial = purchase.trialLengthText, purchase.trialEligible {
            return "TLS Inspection Monthly: free for \(trial), then \(renewal) Payment is charged to your Apple Account when the trial ends. Cancel at least 24 hours before the trial ends to avoid being charged. \(cancel)"
        }
        return "TLS Inspection Monthly: \(renewal) Payment is charged to your Apple Account. \(cancel)"
    }

    /// Status line and Manage Subscription, shown whenever StoreKit reports a subscription state.
    @ViewBuilder
    private var subscriptionStatusRows: some View {
        if let status = accessStatusText {
            Text(status)
                .font(.caption)
                .foregroundColor(purchase.subscriptionState == .billingRetry ? AppColors.warning : .secondary)
        }
        if purchase.subscriptionState != .none {
            Button("Manage Subscription") { showManageSubscriptions = true }
                .font(.footnote)
        }
    }

    private var accessStatusText: String? {
        switch purchase.subscriptionState {
        case .active(let date):    return "Subscribed. Renews \(date.formatted(date: .abbreviated, time: .omitted))."
        case .cancelled(let date): return "Subscription ends \(date.formatted(date: .abbreviated, time: .omitted))."
        case .billingRetry:        return "Payment issue. Update your payment method in Manage Subscription to keep access."
        case .expired, .none:      return nil
        }
    }

    private var restoreButton: some View {
        Button("Restore Purchases") { run { await purchase.restore() } }
            .font(.footnote)
            .disabled(purchaseInFlight)
    }

    private var legalLinks: some View {
        HStack(spacing: 16) {
            Link("Terms of Use", destination: Self.termsURL)
            Link("Privacy Policy", destination: Self.privacyURL)
        }
        .font(.footnote)
    }

    private static let termsURL = URL(string: "https://www.apple.com/legal/internet-services/itunes/dev/stdeula/")!
    private static let privacyURL = URL(string: "https://shapehaveninnovations.com/privacy.html")!

    private func run(_ operation: @escaping () async -> Void) {
        guard !purchaseInFlight else { return }
        purchaseInFlight = true
        Task {
            await operation()
            purchaseInFlight = false
        }
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
            activeSheet = nil
        }
    }

    private var pastePEMSheet: some View {
        PastePEMSheet { text, password in
            do { try handlePastedPEM(text: text, password: password) }
            catch { showImportError = error.localizedDescription }
            activeSheet = nil
        }
    }

    private var generateCASheet: some View {
        GenerateCASheet { confirmed in
            activeSheet = nil
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
            activeSheet = nil
        } onCancel: {
            activeSheet = nil
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
            dnsChips(for: $dnsPrimary) { SharedSettings.dnsPrimary = $0 }
            HStack {
                Text("Secondary")
                Spacer()
                TextField("8.8.4.4", text: $dnsSecondary)
                    .keyboardType(.numbersAndPunctuation)
                    .multilineTextAlignment(.trailing)
                    .onChange(of: dnsSecondary) { _, newValue in SharedSettings.dnsSecondary = newValue }
            }
            dnsChips(for: $dnsSecondary) { SharedSettings.dnsSecondary = $0 }
        } header: {
            Text("DNS Server")
        } footer: {
            Text("Used for DNS lookups while capturing; that provider can see them. Defaults to Google (8.8.8.8, 8.8.4.4). Invalid entries are ignored. Changes take effect on the next tunnel restart.")
                .font(.caption)
        }
    }

    /// Provider chips for one DNS field, so primary and secondary can each be any provider.
    private func dnsChips(for field: Binding<String>, save: @escaping (String) -> Void) -> some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(dnsSuggestions, id: \.label) { s in
                    Button { field.wrappedValue = s.value; save(s.value) } label: {
                        Text(s.label)
                            .font(.caption)
                            .padding(.horizontal, 10).padding(.vertical, 5)
                            .background(Color(.tertiarySystemBackground))
                            .clipShape(Capsule())
                    }
                    .buttonStyle(.borderless)
                }
            }
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

    // Experimental, see SharedSettings.includeAllNetworksInCapture. Off by
    // default (matches today's behavior). Only takes effect on the next
    // Start Capture, since it's part of the tunnel's saved VPN config, not
    // something changeable while a capture is already running. When on,
    // AppCoordinator auto-starts a network scan once the tunnel connects,
    // so the user never has to know about the separate header Scan button.
    private var captureRoutingSection: some View {
        Section {
            Toggle("Include LAN traffic in capture", isOn: Binding(
                get: { includeAllNetworks },
                set: { val in
                    includeAllNetworks = val
                    SharedSettings.includeAllNetworksInCapture = val
                }
            ))
        } footer: {
            Text("Experimental. Routes same-subnet LAN traffic through the capture relay. When this is on, starting a capture automatically runs a network scan so there is LAN traffic to capture; the relay can add latency to that scan. Takes effect the next time you start a capture.")
        }
    }

    // MARK: - About

    private var aboutSection: some View {
        Section("About") {
            Text("This product uses the NVD API but is not endorsed or certified by the NVD.")
                .font(.caption)
                .foregroundColor(.secondary)
            // The TLS gate already shows these links while access is locked.
            if purchase.hasAccess { legalLinks }
        }
    }
}

// MARK: - TLS sheet routing

private enum TLSSheet: Identifiable, Hashable {
    case importPicker, pastePEM, generateCA, tlsWarning
    var id: Self { self }
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
                Text("mDNSShark will act as a TLS proxy for all HTTPS traffic.\n\n• Your CA certificate must be installed and trusted in iOS Settings → General → VPN & Device Management.\n• Add certificate-pinned apps (banking, health) to the Bypass List or they will fail.\n• QUIC (HTTP/3) traffic is blocked while this is on, so sites fall back to regular HTTPS that can actually be inspected. Some sites may feel slightly slower.\n• See the README for full setup steps.")
                    .font(.body)
                    .multilineTextAlignment(.center)
                    .padding()
                Button("I understand - Enable", action: onEnable)
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
