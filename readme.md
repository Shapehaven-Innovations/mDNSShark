## mDNSShark

mDNSShark is an **open-source** iPhone app that shows what is on your local network. It uses Multicast DNS (mDNS), DNS-SD, and SSDP to find printers, media servers, IoT gadgets, and other services on your Wi-Fi, with no setup.

**Quick links:** [Features](#core-features) · [Security](#security-assessment) · [TLS Inspection setup](#setting-up-tls-inspection) · [Contribute](#contribute-and-collaborate)

## Simplicity and Privacy

Every scan runs on your phone, with **no external servers**. The one exception is a button you tap yourself: **Refresh CISA Data** on the Security tab downloads CISA's public vulnerability catalog and asks NIST's National Vulnerability Database (NVD) about specific device vendors. Your device list and scan results are never uploaded, but those NVD queries do name vendors seen on your network (see [Security Assessment](#security-assessment)). There is no telemetry, no analytics, and no trackers. The only permission the app needs is local network access.

<details>
<summary><strong>Terms in a Hurry</strong></summary>

- **TCP**: reliable, ordered connections (web pages, SSH). **UDP**: fire-and-forget packets (DNS, video calls).
- **SYN / SYN-ACK / ACK**: the three steps of a TCP handshake. **FIN**: "I'm done sending." **RST**: "abort now."
- **MSS**: the largest TCP payload per packet (1460 bytes here).
- **DNS**: turns names into IP addresses. **mDNS**: the same, for `.local` names on your LAN, with no server.
- **TLS**: the encryption behind HTTPS. **SNI**: the hostname a client announces at the start of a TLS handshake.
- **CA**: a certificate authority, whose signature makes a certificate trusted.
- **MITM**: a middle party that terminates TLS and re-encrypts it. That is what TLS Inspection does, with your consent.
- **QUIC**: HTTP/3, encrypted web traffic over UDP.
- **VPN / packet tunnel**: an iOS extension that receives the IP packets iOS routes into it. Here nothing leaves for a remote server.
- **pcap**: the standard packet capture file format, openable in Wireshark.
- **LAN**: your local Wi-Fi network.

</details>

## Core Features

- **Bonjour/mDNS (DNS-SD)**: Finds AirPlay receivers, printers, file sharing, and more.
- **SSDP**: Finds UPnP devices such as smart TVs and internet gateways.
- **Local Subnet Scans**: Optionally scans the /24 subnet for common TCP services that don't broadcast.
- **OUI Lookups**: Matches a device's MAC-like address to its manufacturer.
- **Security Assessment**: Flags risky exposed services and checks each manufacturer against CISA's Known Exploited Vulnerabilities (KEV) catalog and the NVD.
- **TLS Inspection**: A local HTTPS proxy, built on a PacketTunnel extension, that decrypts and logs HTTPS traffic for analysis. Available as a monthly subscription with a free 3-day trial.

## Security Assessment

The Security tab turns scan results into findings, grouped by severity, by device, or as one list, and exportable as a plain-text report. Everything is computed on-device from what the scan found.

### What it checks

Each device is assessed in three layers (code: `mDNSShark/Security/SecurityViewModel.swift`):

- **Exposed ports.** Telnet, FTP, VNC, and RDP are Critical. SMB, NetBIOS, SSH, and RTSP are Warnings. UPnP and plain or admin HTTP/HTTPS are Informational.
- **Bonjour services.** The same idea for services a device announces over mDNS (`_telnet._tcp`, `_ssh._tcp`, `_smb._tcp`, and so on).
- **Manufacturer advisories.** The device's manufacturer, as identified by the scan, is matched by whole word against 27 vendors in `mDNSShark/Resources/nist_cpe_map.json` (`vendorAdvisories`). A matched vendor is then checked against:
  - **CISA KEV** for 18 vendors (ASUS, NETGEAR, D-Link, TP-Link, Zyxel, QNAP, MikroTik, Ubiquiti, Hikvision, Dahua, DrayTek, Tenda, Reolink, TerraMaster, Netis, Edimax, Arcadyan, DZS).
  - **NVD** for 10 vendors that KEV barely covers, mostly ISP gateway makers (Arris/CommScope, Technicolor/Vantiva, Sagemcom, Humax, Sercomm, Askey, Hitron, Calix, GL.iNet, DZS). Rejected and Low-rated CVEs are dropped.

A manufacturer match means the vendor has known vulnerabilities somewhere in its product line, **not** that this device does. The app doesn't know the model or firmware version. So each device gets at most one grouped vendor finding, rated **Warning** (any KEV entry, or any NVD Critical/High) or **Informational** (NVD Medium only), and these are left out of the "vulnerable devices" count. CVEs appear as tappable capsules by tier, and each expands into a list linking to nvd.nist.gov.

<details>
<summary>Where the data comes from, and limitations</summary>

- **Bundled KEV snapshot.** `mDNSShark/Resources/cisa_kev_snapshot.json` holds the KEV entries for the vendors above. Regenerate it with `python3 scripts/update_kev_snapshot.py`. NVD data is never bundled.
- **Refresh.** Only the **Refresh CISA Data** button starts one. `ThreatDatabase` runs two phases:
  1. **KEV.** Downloads the catalog from cisa.gov, checks it looks complete, filters it to the vendor table, and merges it over the bundled snapshot. An older cached catalog never overrides a newer bundled one.
  2. **NVD.** Queries only vendors on the current scan or seen in the last 30 days, skipping any fetched in the last 24 hours. Requests are spaced 6.5 seconds apart to respect NVD's rate limit, and each vendor's result is saved as it finishes. Most home networks have zero or one such vendor.
- **Cache.** Refreshed data lives in `Application Support/ThreatData/`, excluded from backups. The Security tab shows whether CISA and NVD data is bundled or refreshed, and flags anything over 30 days old.
- **Not during capture.** Refresh is disabled while the capture tunnel is up, and starting a capture cancels a refresh in progress. Otherwise the download would pass through the capture, and be decrypted by the app's own interceptor if TLS Inspection is on.

This product uses the NVD API but is not endorsed or certified by the NVD.

### Limitations

- Vendor-level only. Devices with an unidentified or unlisted manufacturer get no advisory finding.
- The port scanner captures SSH and HTTP banners that often include software versions, but they are not yet matched against NVD. Per-device version matching is tracked in `todo.md`.

</details>

## TLS Inspection

TLS Inspection makes mDNSShark a local man-in-the-middle proxy for HTTPS traffic through the device. It runs in a `PacketTunnel` Network Extension, entirely on-device.

To turn it on, jump to [Setting Up TLS Inspection](#setting-up-tls-inspection).

### Which Mode Do I Want?

Two Settings toggles combine: **Include LAN traffic** and **Enable TLS Inspection**. Internet works in all four modes.

| Mode | What is captured | What is not | Use it for |
| ---- | ---------------- | ----------- | ---------- |
| LAN off, TLS off | This phone's internet traffic, encrypted | Decrypted HTTPS, LAN traffic | Seeing who the phone talks to (DNS, SNI, ports) |
| LAN off, TLS on | Same, plus decrypted HTTPS requests. UDP/QUIC on 443 is dropped so apps fall back to TCP | LAN traffic | Reading what apps send over HTTPS |
| LAN on, TLS off | Adds this phone's traffic to other devices on the Wi-Fi subnet (scan probes appear) | Decrypted HTTPS | Seeing what a LAN scan sends |
| LAN on, TLS on | Everything above, plus decrypted HTTPS to a LAN host by IP on port 443, with no certificate warning (tested with one self-signed host) | Nothing extra | Inspecting a device's web interface |

In every mode, the router's own traffic and other devices' traffic are never seen.

### Pricing

Discovery, subnet scans, and OUI lookups are free. TLS Inspection is the one paid feature: a **monthly subscription** with a **free 3-day trial**, cancelable any time in Settings > Apple Account > Subscriptions. Prices are set in App Store Connect and shown live in Settings. The subscription funds safe maintenance of an on-device certificate-generating proxy. If you'd rather contribute code, see [Contribute and Collaborate](#contribute-and-collaborate).

<details>
<summary>How it works, and diagnostics (for contributors)</summary>

`NEPacketTunnelProvider` hands the extension raw IPv4 packets with no socket API. So the extension acts as the device's TCP peer, its TLS server, and a TLS client to the real site. Code: `PacketTunnel/` (`PacketForwarder.swift`, `TLSInterceptor.swift`, `ChecksumHelpers.swift`).

Each connection takes one of two paths:

- **Plain relay** (TCP and UDP): the extension opens an `NWConnection` to the real server, sends SYN-ACK once it is ready, and relays bytes both ways.
- **Intercept**: used for TCP 443 when TLS Inspection is on and a CA key and certificate are present. The extension sends SYN-ACK at once, reads the SNI from the ClientHello, completes TLS with the device using a freshly minted leaf certificate, opens TLS to the real server, logs the decrypted requests, then flushes the response and closes.

Replies are hand-built IPv4/TCP packets with real checksums and segments up to the 1460-byte MSS.

Implementation notes:

- **MSS:** without the 1460 option the kernel sent 512-byte segments, so the SNI parser accepts a split `ClientHello`.
- **Sequence numbers:** only in-window segments advance `clientSeq`. Acking unsent bytes makes the kernel discard everything we send (RFC 9293 §3.10.7.4).
- **FIN:** ack `deviceFINSeq + 1`. One short and the device retransmits its FIN for about 18 seconds.
- **TLS bridge:** device and upstream TLS are joined through an `NWListener` pinned to `127.0.0.1`. A wildcard listener timed out on device.
- **Upstream trust:** verification is skipped only for private-IP destinations with no SNI, an IP SNI, a `.local` name, or a dotless name.
- **Timeouts:** 5 seconds for listener, loopback connect, and accept, and 10 for upstream, since Network.framework reports establishment failures as `.waiting`, not `.failed`.
- **Leaf certs:** EC P-256, valid for 25 hours starting one hour back, issued by the CA subject, with keys in the shared keychain access group and a 200-domain cache purged when the tunnel stops.

### Diagnostics

Console access to a network extension on a real iPhone is unreliable, so the extension reports on itself. These are intentional; do not remove them as dead code.

- **Error banner** (`tlsInterceptorLastError`): the app shows the extension's last non-benign drop reason in a dismissible banner. `tlsInterceptorDropCount` still counts drops, but its Settings line is disabled.
- **Unified log:** `log stream --level debug --predicate 'subsystem == "com.mDNSShark.PacketTunnel"'`. Key lines: `sendSYNACK to ...`, `device-facing TLS READY` (the device trusted the leaf), and `first write to device`.
- **Packet capture:** the `.pcap` export includes the extension's own synthetic packets, tagged `[reconstructed]` in the capture view.
- **Signposts:** each plain relay flow is an `OSSignposter` interval (`relayFlow`) in Instruments.

</details>

### Setting Up TLS Inspection

TLS Inspection needs a CA certificate that iOS trusts as a root. This has two halves, and the second is easy to miss: getting the CA into mDNSShark's keychain (so the extension can sign leaves), and installing the same CA as a trusted profile in iOS (so Safari and other apps accept those leaves). `Generate CA…` only does the first half. Until the second is done, every intercepted connection fails its handshake.

Settings offers three ways to get a CA:

| Option                 | When to use                                                   |
| ---------------------- | ------------------------------------------------------------- |
| **Import from Files…** | You have an existing `.cer`, `.pem`, or `.p12` / `.pfx` file  |
| **Paste PEM / P12…**   | You want to paste raw PEM certificate and/or private key text |
| **Generate CA…**       | You want mDNSShark to create a new CA key pair on-device      |

`Generate CA…` creates a P-256 key pair and a self-signed CA (`CN=mDNSShark CA`, valid three years), stores both in the keychain, and exports `mDNSShark-CA.cer` through the share sheet. If you import or paste a CA, include the **private key**; a certificate alone cannot sign leaves.

**Installing and trusting the CA:**

1. In mDNSShark, go to **Settings → TLS Inspection**, subscribe (the free trial starts here), then tap **Generate CA…**. The certificate buttons appear once you have access.
2. In the share sheet, choose **Save to Files**.
3. In the **Files** app, tap the saved `mDNSShark-CA.cer`. iOS shows "Profile Downloaded".
4. Go to iOS **Settings → General → VPN & Device Management**, tap the mDNSShark CA profile, and tap **Install**.
5. Go to **Settings → General → About → Certificate Trust Settings** and turn on **Enable Full Trust for Root Certificates** for the mDNSShark CA.
6. Back in mDNSShark Settings, turn on **Enable TLS Inspection**.

A warning sheet appears the first time you enable the feature.

The iOS trust profile survives rebuilds and reinstalls. If Settings shows "Install a CA certificate to enable" after a reinstall, generate or import again and repeat from step 3. A new CA is a different certificate, and the old profile won't trust its leaves.

### TLS Bypass List

Apps that use certificate pinning (banking, health, government) fail if intercepted. Add their domains to the **TLS Bypass List** in Settings:

- Enter a domain suffix (e.g. `bank.com`) and tap **+**.
- Any connection whose SNI ends with a listed suffix is passed through uninspected.
- Swipe left to delete an entry.

**Always add Apple's own services.** `push.apple.com` (APNs), `icloud.com` (including Private Relay), and `apple-native-relay.apple.com` (Private Relay's egress) are certificate-pinned and resist MITM by design. This is not a bug in `TLSInterceptor.swift`. Without these entries, their failed sessions flood the extension's drop log (`apple-native-relay.apple.com` fails with `-9830: errSSLIllegalParam`) and bury real errors. The bypass list **can be cleared by a rebuild or reinstall**, so re-add all three after a fresh install.

### DNS Server

The extension uses configurable upstream DNS resolvers, a primary and a secondary. Settings has quick-select chips for Cloudflare (`1.1.1.1`), Quad9 (`9.9.9.9`), and Google (`8.8.8.8`). The default is Google Public DNS (`8.8.8.8`, `8.8.4.4`), so that provider sees lookups made during a capture. Only IPv4 addresses are accepted, and if none are valid the defaults are used. Changes apply on the next tunnel restart.

### Capture Filters

The **Capture** section in Settings has a chip for each protocol the capture view can show: `DNS`, `mDNS`, `HTTPS`, `HTTP`, `TCP`, `UDP`, `ICMP`. Tap a chip to turn it on or off. All are on by default.

<details>
<summary>Shared settings and certificate storage (for contributors)</summary>

TLS settings live in a shared `UserDefaults` suite (`group.beta.mDNSShark`) so the app and the extension read the same configuration:

| Key                       | Type            | Default       |
| ------------------------- | --------------- | ------------- |
| `tlsInspectionEnabled`    | Bool            | `false`       |
| `tlsSubscriptionExpiry`   | Date?           | `nil`         |
| `tlsBypassList`           | JSON `[String]` | `[]`          |
| `dnsPrimary`              | String          | `8.8.8.8`     |
| `dnsSecondary`            | String          | `8.8.4.4`     |
| `captureFilterProtocols`  | JSON `[String]` | all protocols |
| `tlsInterceptorDropCount` | Int             | `0`           |
| `tlsInterceptorLastError` | String          | `""`          |

`PurchaseManager` mirrors the subscription or trial end date from StoreKit into `tlsSubscriptionExpiry`, since the extension has no StoreKit access. The extension checks it every 60 seconds, so an expired subscription or a refund turns interception off without a restart.

`tlsInterceptorDropCount` and `tlsInterceptorLastError` flow the other way, from the extension to Settings. They are the [Diagnostics](#diagnostics) channel and are meant to stay.

### Certificate Storage

CA and leaf material is stored in the iOS Keychain under the shared access group `group.beta.mDNSShark`:

| Item                              | Keychain class                            |
| --------------------------------- | ----------------------------------------- |
| CA certificate (`SecCertificate`) | `kSecClassCertificate`                    |
| CA private key (`SecKey`)         | `kSecClassKey`                            |
| Per-domain leaf private keys      | `kSecClassKey` (tag `mdns.leaf.<domain>`) |
| Per-domain leaf certificates      | `kSecClassCertificate`                    |

**Remove Certificate** in Settings purges all CA items and disables inspection. Stopping the tunnel calls `LeafCertCache.purge()`, which deletes leaf items.

</details>

## System Requirements

1. **Device**: iPhone only.
2. **iOS**: 18.2 or later, for the app and the `PacketTunnel` extension.
3. **Network**: Wi-Fi is recommended for full scanning.
4. **Development (optional)**: a recent **Xcode** (verified with 26.5). TLS Inspection can't be tested in the Simulator; the extension and the CA trust flow need a real device.

## Contribute and Collaborate

- **Open Issues**: Report bugs or request features.
- **Pull Requests**: Share improvements or experiments.
- **Discussions**: Suggest changes or ask questions.
- **Code Comments**: Found a rough edge or a "why is this here" moment? Comment on a PR or open an issue. Annotating existing code is a low-friction way to help.

You don't need to be a Swift expert. Reporting a confusing UI flow, testing on a device we don't have, or asking "why does it work this way?" all help.

**No data collection, no lengthy setups, just on-device network discovery.**
