## mDNSShark

mDNSShark is an **open-source** iPhone application created by a small team of engineers who wanted a simpler, clearer way to explore local networks. By tapping into protocols like Multicast DNS (mDNS), DNS-SD, and SSDP, mDNSShark quickly uncovers printers, media servers, IoT gadgets, and other active services on your home or office Wi-Fi - no convoluted setup required. If you've ever wondered what devices are really on your network, or how various services talk to each other, mDNSShark is designed to give you those answers efficiently and privately.

## Simplicity and Privacy

Simplicity is key: we've stripped away clutter so you can focus on scanning and understanding results. Every discovery operation runs right on your phone, with **no external servers** involved. We also do **not** collect or share any usage data - there's no telemetry, no user analytics, and certainly no hidden trackers. You remain fully in control, deciding if and when to allow local network access, which is all the app needs to function.

## Built by Engineers, Open to Everyone

mDNSShark was created by engineers who love transparent, lightweight solutions - yet it's also friendly for anyone curious about local network behavior. If you're a fellow engineer, a technologist, or just someone who enjoys problem-solving, you'll find plenty of ways to contribute. Newcomers can help refine the interface, add new features, or even propose deeper networking enhancements. Veterans can dive into advanced scanning logic, integrate emergent protocols, and optimize performance. We firmly believe that collectively, we can build an indispensable network tool for iPhone users everywhere.

## Current Development

mDNSShark is still **in active development**, with regular updates that refine performance, expand support for various network protocols, and polish the user experience. We welcome your ideas - whether it's a new device detection trick, an easier UI flow, or an innovative scanning feature. Our public repository provides a transparent view of current issues and ongoing discussions, letting you jump in wherever your skills or interests fit best.

## Core Features at a Glance

- **Bonjour/mDNS (DNS-SD)**: Identifies devices like AirPlay receivers, printers, or file-sharing services through built-in discovery.
- **SSDP**: Finds devices that speak UPnP, such as smart TVs or internet gateways.
- **Local Subnet Scans**: Optionally scans the /24 subnet to uncover common TCP-based services, even if they aren't broadcasting via Bonjour or SSDP.
- **OUI Lookups**: Matches a device's MAC-like address to manufacturers, giving quick hardware insights.
- **TLS Inspection**: Acts as a local HTTPS proxy via a PacketTunnel extension to decrypt and log HTTPS traffic for analysis.
- **Minimalist Interface**: Straight to the point - run a scan, view your devices, dig into details as needed.

## TLS Inspection

TLS Inspection lets mDNSShark act as a local man-in-the-middle proxy for HTTPS traffic flowing through the device. It is powered by a `PacketTunnel` Network Extension and runs entirely on-device - no traffic leaves to external servers.

### How It Works

When enabled, the tunnel intercepts outbound TCP connections on port 443. It:

1. Parses the TLS `ClientHello` to extract the **Server Name Indication (SNI)** hostname.
2. Generates a short-lived leaf certificate (valid ~25 hours) signed by your installed CA, using an EC P-256 key pair stored in the iOS Keychain inside a shared App Group.
3. Completes a TLS handshake with the device using that leaf cert, then opens a separate TLS connection to the real upstream server.
4. Passes plaintext request data to the packet capture view and relays responses back - the device sees valid TLS throughout.

Leaf certificates are cached in memory per domain (`LeafCertCache`) and cleaned up when the tunnel stops.

### Setting Up TLS Inspection

TLS Inspection requires a trusted CA certificate before it can be enabled. The Settings screen offers three options:

| Option                 | When to use                                                   |
| ---------------------- | ------------------------------------------------------------- |
| **Import from Files…** | You have an existing `.cer`, `.pem`, or `.p12` / `.pfx` file  |
| **Paste PEM / P12…**   | You want to paste raw PEM certificate and/or private key text |
| **Generate CA…**       | You want mDNSShark to create a new CA key pair on-device      |

**After obtaining the CA certificate:**

1. Go to **Settings → TLS Inspection** inside mDNSShark.
2. Choose one of the three import methods above.
3. Open iOS **Settings → General → VPN & Device Management** and install the exported `.cer` file as a trusted root.
4. Go to iOS **Settings → General → About → Certificate Trust Settings** and enable full trust for the mDNSShark CA.
5. Return to mDNSShark Settings and toggle **Enable TLS Inspection** on.

A warning sheet is shown the first time you enable the feature to confirm you understand the implications.

### TLS Bypass List

Not all apps tolerate a TLS proxy - apps that use certificate pinning (banking, health, government) will fail to connect if intercepted. Add those domains to the **TLS Bypass List** in Settings:

- Enter a domain suffix (e.g. `bank.com`) and tap **+**.
- Any connection whose SNI ends with a listed suffix is passed through uninspected.
- Delete entries with a swipe-left gesture.

Pre-populate the bypass list with any certificate-pinned apps before enabling inspection.

### DNS Server

The PacketTunnel extension uses configurable upstream DNS resolvers. Two servers can be set (primary and secondary). Quick-select chips for common providers (Cloudflare `1.1.1.1`, Quad9 `9.9.9.9`, Google `8.8.8.8`) are available in Settings. Changes take effect on the next tunnel restart.

### Capture Filters

The **Capture Filters** section in Settings lets you choose which protocol families are displayed in the packet capture view. Supported protocol labels: `DNS`, `mDNS`, `HTTPS`, `HTTP`, `TCP`, `UDP`, `ICMP`. All are enabled by default; toggle any off to reduce noise.

### Shared Settings (App Group)

All TLS settings are stored in a shared `UserDefaults` suite (`group.org.shapehaveninnovations.mDNSShark`) so the main app and the PacketTunnel extension read the same configuration without IPC overhead. The relevant keys are:

| Key                       | Type            | Default       |
| ------------------------- | --------------- | ------------- |
| `tlsInspectionEnabled`    | Bool            | `false`       |
| `tlsBypassList`           | JSON `[String]` | `[]`          |
| `dnsPrimary`              | String          | `8.8.8.8`     |
| `dnsSecondary`            | String          | `8.8.4.4`     |
| `captureFilterProtocols`  | JSON `[String]` | all protocols |
| `tlsInterceptorDropCount` | Int             | `0`           |

### Certificate Storage

CA and leaf certificate material is stored in the iOS Keychain under the shared access group `group.org.shapehaveninnovations.mDNSShark`:

| Item                              | Keychain class                            |
| --------------------------------- | ----------------------------------------- |
| CA certificate (`SecCertificate`) | `kSecClassCertificate`                    |
| CA private key (`SecKey`)         | `kSecClassKey`                            |
| Per-domain leaf private keys      | `kSecClassKey` (tag `mdns.leaf.<domain>`) |
| Per-domain leaf certificates      | `kSecClassCertificate`                    |

Tapping **Remove Certificate** in Settings purges all CA items and disables inspection. Stopping the tunnel calls `LeafCertCache.purge()` which deletes all in-flight leaf items.

## System Requirements

1. **Device**: iPhone only.
2. **iOS Version**: **iOS 16 or later** for `NWListener`, `Network.framework` TLS APIs, and SwiftUI features used in the Settings and packet views.
3. **Network**: A reliable Wi-Fi connection is recommended for full scanning capabilities.
4. **Development (Optional)**: To build or modify the code, you'll need **Xcode 15 or above** and Swift 5.9 or later.

## Contribute and Collaborate

We're always eager for fresh ideas and extra sets of eyes on the code:

- **Open Issues**: Let us know if you spot bugs or would like a new feature.
- **Pull Requests**: Share your improvements or experiments with the community.
- **Discussions**: Suggest changes, ask questions, or explore new scanning methods.

mDNSShark is grounded in the principle that local network exploration doesn't have to be intimidating - or invasive. We're building a community-driven tool that emphasizes clarity, privacy, and inclusivity, so anyone can understand and troubleshoot what's happening on their own network. Whether you're an experienced developer or just love tinkering, mDNSShark can use your passion and expertise.

Join us to help shape the future of straightforward, on-device network discovery - **no data collection, no lengthy setups, just powerful scanning for everyone.**
