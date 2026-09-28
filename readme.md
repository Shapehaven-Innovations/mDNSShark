## mDNSShark

mDNSShark is an **open-source** iPhone application created by a small team of engineers who wanted a simpler, clearer way to explore local networks. By tapping into protocols like Multicast DNS (mDNS), DNS-SD, and SSDP, mDNSShark quickly uncovers printers, media servers, IoT gadgets, and other active services on your home or office Wi-Fi - no convoluted setup required. If you've ever wondered what devices are really on your network, or how various services talk to each other, mDNSShark is designed to give you those answers efficiently and privately.

## Simplicity and Privacy

Simplicity is key: we've stripped away clutter so you can focus on scanning and understanding results. Every discovery operation runs right on your phone, with **no external servers** involved. The one exception is a button you tap yourself: **Refresh CISA Data** on the Security tab downloads CISA's public vulnerability catalog and asks NIST's National Vulnerability Database about specific device vendors. Your device list and scan results are never uploaded, but those NVD queries do name vendors seen on your network (see [Security Assessment](#security-assessment)). We also do **not** collect or share any usage data - there's no telemetry, no user analytics, and certainly no hidden trackers. You remain fully in control, deciding if and when to allow local network access, which is all the app needs to function.

## Built by Engineers, Open to Everyone

mDNSShark was created by engineers who love transparent, lightweight solutions - yet it's also friendly for anyone curious about local network behavior. If you're a fellow engineer, a technologist, or just someone who enjoys problem-solving, you'll find plenty of ways to contribute. Newcomers can help refine the interface, add new features, or even propose deeper networking enhancements. Veterans can dive into advanced scanning logic, integrate emergent protocols, and optimize performance. We firmly believe that collectively, we can build an indispensable network tool for iPhone users everywhere.

## Current Development

mDNSShark is still **in active development**, with regular updates that refine performance, expand support for various network protocols, and polish the user experience. We welcome your ideas - whether it's a new device detection trick, an easier UI flow, or an innovative scanning feature. Our public repository provides a transparent view of current issues and ongoing discussions, letting you jump in wherever your skills or interests fit best.

### Recent improvements

- **More reliable first scans.** On some devices, the very first scan after
  installing (or right after a fresh permission prompt) could come back
  with no device details at all - the scan was starting a moment before
  iOS finished confirming local-network access. Scans now wait for that
  confirmation first.
- **Better device identification for more routers.** Manufacturer and OS
  detection now looks at more of what a device's admin page actually sends
  back, rather than just the page title - catching vendors (GL.iNet
  routers, among others) that were previously showing as Unknown despite
  being fully reachable.
- **TLS Inspection actually completes handshakes on real hardware.** A long
  on-device debugging run fixed a chain of problems in the packet-tunnel
  extension's hand-built TCP: zeroed IP/TCP checksums the kernel silently
  dropped, a missing MSS option, response segments larger than the MSS,
  FINs that were never acknowledged (the device retransmitted them for
  ~18 seconds before giving up), and a packet capture that only recorded
  one side of the conversation. The details are in
  [Under the Hood](#under-the-hood-a-userspace-tcp-stack-inside-a-packet-tunnel)
  below.
- **Plain (non-TLS) TCP through the tunnel now completes a real handshake.**
  The same packet-tunnel extension previously never synthesized a SYN-ACK
  or tracked real sequence numbers for ordinary TCP, which meant LAN scan
  probes routed through capture never actually connected. Fixed alongside
  five routing issues that kept LAN traffic from ever reaching the tunnel
  in the first place (`excludeLocalNetworks`, a tunnel/Wi-Fi subnet
  collision, `enforceRoutes`, an explicit on-link route, and a `NetService`
  retention bug that looked related but wasn't). Verified on-device against
  a real 254-host subnet sweep with zero bad checksums and clean teardown
  on every connection.
- **Starting a capture with "Include LAN traffic" on now runs a scan
  automatically.** Previously, seeing any LAN traffic in a capture required
  separately tapping the header bar's **Scan** button — nothing in the UI
  said this was necessary, and the toggle alone produced an empty capture.
  The app now starts a scan itself once the tunnel actually connects.
- **Security findings now check device manufacturers against live
  vulnerability data.** The old system mapped a fixed handful of CVEs at
  build time, and most of the ones labeled "CISA" were never actually in
  CISA's catalog. The Security tab now matches each device's manufacturer
  against CISA's Known Exploited Vulnerabilities (KEV) catalog and NIST's
  National Vulnerability Database (NVD), and a refresh can surface CVEs
  the app didn't ship with. Details in
  [Security Assessment](#security-assessment) below.
- **Fewer false CRITICAL findings.** Any device advertising FTP, Telnet, or
  VNC used to be stamped CRITICAL for specific CVEs in software it might
  not even run (e.g. the vsftpd 2.3.4 backdoor on any FTP server). Those
  are gone; the plain "FTP exposed"-style findings remain.
- **Open ports on TLS 1.2-only devices are no longer lost.** The port
  scanner's HTTPS probe required TLS 1.3, so many routers and embedded
  devices that only speak TLS 1.2 silently lost their open-port findings.
- **Readable CVE lists.** A vendor with dozens of CVEs used to produce one
  long comma-separated wall of IDs. Findings now show tappable severity
  capsules that expand into a per-CVE list, each linking to its NVD page.

## Core Features at a Glance

- **Bonjour/mDNS (DNS-SD)**: Identifies devices like AirPlay receivers, printers, or file-sharing services through built-in discovery.
- **SSDP**: Finds devices that speak UPnP, such as smart TVs or internet gateways.
- **Local Subnet Scans**: Optionally scans the /24 subnet to uncover common TCP-based services, even if they aren't broadcasting via Bonjour or SSDP.
- **OUI Lookups**: Matches a device's MAC-like address to manufacturers, giving quick hardware insights.
- **Security Assessment**: Flags risky exposed services and checks each device's manufacturer against CISA's Known Exploited Vulnerabilities catalog and the NVD.
- **TLS Inspection**: Acts as a local HTTPS proxy via a PacketTunnel extension to decrypt and log HTTPS traffic for analysis. Free for a 3-day trial, then a one-time unlock supports continued development.
- **Minimalist Interface**: Straight to the point - run a scan, view your devices, dig into details as needed.

## Security Assessment

The Security tab turns scan results into findings, grouped by severity, by device, or as one list, and exportable as a plain-text report. Everything here is computed on-device from what the scan already found.

### What it checks

Each device is assessed in three layers (all in `mDNSShark/Security/SecurityViewModel.swift`):

- **Exposed ports.** Fixed rules per open port: Telnet, FTP, VNC, and RDP are Critical; SMB, NetBIOS, SSH, and RTSP are Warnings; UPnP and plain or admin HTTP/HTTPS are Informational.
- **Bonjour-advertised services.** The same idea for services a device announces over mDNS (`_telnet._tcp`, `_rfb._tcp`, `_ssh._tcp`, `_smb._tcp`, printers, HomeKit, and so on).
- **Manufacturer advisories.** The device's manufacturer, as identified by the scan (OUI lookup, SSDP, admin-page banners, and the other enrichment probes), is matched against a curated table of 27 vendors in `mDNSShark/Resources/nist_cpe_map.json` (`vendorAdvisories`). Matching is by whole word only, so "Harris" never matches Arris. A matched vendor is then checked against:
  - **CISA KEV** for 18 vendors (ASUS, NETGEAR, D-Link, TP-Link, Zyxel, QNAP, MikroTik, Ubiquiti, Hikvision, Dahua, DrayTek, Tenda, Reolink, TerraMaster, Netis, Edimax, Arcadyan, DZS), by exact match on KEV's `vendorProject` field.
  - **NVD** for 10 vendors that KEV barely covers, mostly ISP-supplied gateway makers (Arris/CommScope, Technicolor/Vantiva, Sagemcom, Humax, Sercomm, Askey, Hitron, Calix, GL.iNet, DZS). A CVE counts only if its description names the vendor as a whole word, or one of its CPE entries lists an allowlisted vendor ID. Rejected CVEs and CVEs rated Low are dropped.

A manufacturer match says the vendor has known vulnerabilities somewhere in its product line, **not** that this particular device has them. The app does not know the device's model or firmware version. Because of that, each device gets at most one grouped vendor finding, never more than **Warning** (any KEV entry, or any NVD Critical/High) or **Informational** (NVD Medium only). These findings are also left out of the "vulnerable devices" count. The finding shows its CVEs as tappable capsules by tier (`N KEV`, `N High/Crit`, `N Medium`). Each capsule expands into a per-CVE list where every row links to that CVE's page on nvd.nist.gov.

### Where the data comes from

- **Bundled KEV snapshot.** `mDNSShark/Resources/cisa_kev_snapshot.json` is the subset of the live KEV catalog filed under a vendor in the table above. Regenerate it from the repo root with `python3 scripts/update_kev_snapshot.py`. NVD data is never bundled; it only arrives through a refresh.
- **Refresh.** Only the **Refresh CISA Data** button on the Security tab starts one; nothing refreshes automatically or in the background. `ThreatDatabase` runs two phases:
  1. **KEV.** Downloads the full catalog from cisa.gov and sanity-checks it (at least 1,000 entries, and a count that matches its own header) so a captive portal or a truncated response can't wipe anything. It then filters the catalog to the vendor table and merges it over the bundled snapshot by CVE ID. A cached catalog older than the bundled one (say, after an app update) never overrides it.
  2. **NVD.** Queries only vendors that are on the current scan or were seen in the last 30 days, and skips any vendor already fetched in the last 24 hours. Most home networks have zero or one such vendor, so this usually takes seconds. Requests are spaced 6.5 seconds apart to stay under NVD's unauthenticated rate limit, and each vendor's result is saved as soon as it finishes, so one failure never discards another vendor's data.
- **Cache.** Refreshed data is stored in `Application Support/ThreatData/`, excluded from backups and file-protected, and survives relaunches. The Security tab's status line shows, separately for CISA and NVD, whether the data is bundled or refreshed, and flags anything over 30 days old.
- **Not during capture.** While the packet-capture tunnel is up, refresh is disabled, and starting a capture cancels a refresh already in progress. The tunnel routes the app's own traffic too, so the download would otherwise pass through the capture and, with TLS Inspection on, be decrypted by the app's own interceptor.

This product uses the NVD API but is not endorsed or certified by the NVD. The same notice appears in Settings, on the Security tab, and in exported reports.

### Limitations

- Vendor-level only. Devices whose manufacturer isn't identified, or isn't in the vendor table, get no advisory finding at all.
- The port scanner already captures SSH and HTTP banners that often include exact software versions, but they are only used for manufacturer/OS guessing today and are not matched against NVD. Per-device version matching is tracked in `todo.md`.

## TLS Inspection

TLS Inspection lets mDNSShark act as a local man-in-the-middle proxy for HTTPS traffic flowing through the device. It is powered by a `PacketTunnel` Network Extension and runs entirely on-device - no traffic leaves to external servers.

If you only want to turn it on, jump to [Setting Up TLS Inspection](#setting-up-tls-inspection). If you want to know how an iPhone app manages to terminate TLS for Safari without a kernel driver, keep reading.

### Pricing

The rest of mDNSShark - discovery, subnet scans, OUI lookups - is free, full stop. TLS Inspection is the one feature behind a paywall: it starts with a **free 3-day trial**, and after that a **one-time unlock** (currently $4.99, set in App Store Connect and shown live in Settings) keeps it enabled. This isn't about locking away the app - it's the mechanism that funds the ongoing work of maintaining a certificate-generating MITM proxy safely on-device. If you'd rather support the project by contributing code instead of paying, see [Contribute and Collaborate](#contribute-and-collaborate) below - PRs are always welcome regardless of trial or unlock status.

### How It Works

`NEPacketTunnelProvider` hands the extension raw IPv4 packets and expects raw IPv4 packets back. There is no socket API in between: if the extension wants a connection to succeed, it has to answer the device's packets itself. For an intercepted HTTPS flow the extension therefore plays three roles at once: it is the device's **TCP peer**, the device's **TLS server**, and a **TLS client** to the real site.

When enabled, the tunnel intercepts outbound TCP connections on port 443. For each one it:

1. Answers the device's SYN with a synthesized SYN-ACK, so the device's kernel believes it is talking to the real server.
2. Buffers the device's first bytes and parses the TLS `ClientHello` to extract the **Server Name Indication (SNI)** hostname.
3. Mints a short-lived leaf certificate for that hostname (valid 25 hours), signed by your installed CA, with a fresh EC P-256 key pair stored in the iOS Keychain inside the shared App Group.
4. Terminates the device's TLS using that leaf cert, then opens a separate TLS connection to the real upstream server.
5. Passes the decrypted request to the packet capture view, relays the response back through the device-facing TLS session, and re-packetizes the encrypted bytes into hand-built TCP segments. The device sees valid TLS throughout.

Leaf certificates are cached in memory per domain (`LeafCertCache`) and cleaned up when the tunnel stops.

### Under the Hood: A Userspace TCP Stack Inside a Packet Tunnel

Everything in this section lives in `PacketTunnel/`. `PacketForwarder.swift` routes packets, `TLSInterceptor.swift` holds the per-flow `TLSSession`, and `ChecksumHelpers.swift` is the shared checksum math. The code is heavily commented, and most comments describe a specific failure that was observed on a real iPhone, so reading the source alongside this section is worthwhile.

#### Two paths through the forwarder

`PacketForwarder` reads every outbound packet and does one of two things:

- **Plain relay** (everything that is not an intercepted 443 flow): open one `NWConnection` per flow, send the payload, and write replies back as hand-built IPv4/UDP or IPv4/TCP packets. This is a userspace NAT. It works for UDP (DNS through the tunnel is how the extension learns IP-to-hostname mappings for the bypass list) and, since the plain-relay rewrite noted under [Recent improvements](#recent-improvements), for TCP as well: the relay synthesizes its own SYN-ACK and tracks real sequence numbers, the same way the intercept path does.
- **Intercept** (port 443, TLS Inspection unlocked and enabled, CA key present): hand the flow to `TLSInterceptor`, which owns it until it closes. The forwarder keeps feeding it the device's later packets, including the empty ACK that completes the handshake, SYN retransmits, and the FIN or RST at the end.

While the interceptor is active the forwarder also drops UDP port 443 outright. QUIC (HTTP/3) needs no synthetic handshake and would win the race against the intercepted TCP path every time, so inspection would silently see nothing for QUIC-capable sites. Dropping the UDP forces the HTTP/3-to-HTTPS fallback every real client already implements, which is the same trick commercial TLS-inspecting middleboxes use.

#### Synthesizing the handshake

`TLSSession.sendSYNACK()` builds the SYN-ACK by hand. A few details matter more than they look:

- **Initial sequence number.** Our ISN starts at a fixed value and is recorded the first time the SYN-ACK is sent. If the device retransmits its SYN (because our first SYN-ACK was rejected), the resent SYN-ACK reuses the exact same ISN. Changing it on retry is itself a protocol violation the device's kernel would reject.
- **Ack number.** The SYN-ACK acknowledges the device's ISN plus one, and `clientSeq` (the next byte we expect from the device) is initialized from the device's ISN in the packet header.
- **MSS option.** The SYN-ACK carries `kind=2 len=4 value=1460`. Without it, the device's kernel falls back to `tcp_mssdflt` (512 bytes). This showed up in a pcap as a 1512-byte ClientHello arriving in three 512-byte segments, which is also why the SNI parser accepts a `ClientHello` that spans more than one segment.
- **Checksums.** `utun` sets no checksum-offload flags, so the receiving kernel verifies both the IPv4 header checksum and the TCP checksum. A zeroed checksum is indistinguishable from a corrupt packet and is dropped without a trace. Both paths now patch in real RFC 1071 checksums via `PacketChecksum`. For a while this was the reason no synthetic packet from either path was ever accepted at all.

#### Keeping sequence numbers honest

`TLSSession` tracks two numbers under one lock: `serverSeq`, the next byte we will send, and `clientSeq`, the next byte we expect from the device (which doubles as our ack number). They are touched from two threads (the forwarder's queue on receive, the proxy thread on send), so every read-modify-write and the `writePackets` that consumes them happen under `seqLock`. Holding the lock across the write also keeps our synthetic packets leaving in sequence order.

`receive(_:seq:)` compares each incoming segment's sequence number against `clientSeq`. An in-window segment advances `clientSeq` and is appended to the inbound buffer. A retransmit or reordered segment is dropped rather than appended, because accepting it would advance `clientSeq` past bytes the device never sent and make our next ack unacceptable (RFC 9293 §3.10.7.4), after which the device's kernel silently drops everything we send. Every call still sends an ACK: in-window segments get their bytes acked, out-of-window ones get a duplicate ack telling the device what to resend.

#### MSS chunking on the way back

`writeToDevice(_:)` splits response data into segments of at most 1460 bytes. A real page easily exceeds that (an 11 KB search results page was the test case), and a single oversized synthetic segment violates both the MSS we advertised and the tunnel's 1500-byte MTU. The device's kernel simply never acks it, which from the outside looked exactly like "the server never answered" until the packet capture started recording our own outbound packets.

#### Closing without a retransmit storm

A FIN consumes one sequence number, but the FIN packet carries no payload and never goes through `receive`, so `clientSeq` was never advanced past it. Acking with the stale value is one byte short of acknowledging the FIN, and on-device the result was the same FIN retransmitted twelve or more times over about 18 seconds before the device gave up with an RST. `close(deviceFINSeq:)` therefore acks `deviceFINSeq + 1`.

Two related cases are handled explicitly in `PacketForwarder` and `close()`:

- Darwin routinely coalesces a final write with the FIN into one segment. The forwarder delivers that payload before closing, and computes the FIN's own sequence number as `tcpSeq + payload.count`.
- Simultaneous close is common here, not an edge case: the upstream server finishing its response triggers our `close()` at nearly the same moment the device sends its own FIN. The FIN-seq correction is applied even when `close()` turns out to be a no-op, otherwise the device's FIN would never be acked in exactly that case.

The session also sends its own FIN when it closes. It does not run a full `FIN_WAIT`/`LAST_ACK` state machine; the session is being torn down regardless, and this is just enough for the device's kernel to stop waiting.

#### The TLS bridge

Rather than embed a TLS library, the extension uses Network.framework's TLS in both directions and bridges the two with a loopback socket:

1. An `NWListener` configured with the per-domain leaf identity is started on `127.0.0.1`. It is pinned to loopback explicitly: inside a packet-tunnel provider, a wildcard-bound listener inherits NECP's VPN-loop-prevention scope to the physical interface, its accepted socket's SYN-ACK to `127.0.0.1` fails source-interface selection (`EADDRNOTAVAIL`) and is dropped silently, and the connect below times out. On-device that was 91 of 91 sessions dropped with `ETIMEDOUT`, all recorded in Settings.
2. A POSIX socket connects to that listener (non-blocking connect plus `poll`, bounded at 5 seconds; a blocking `connect()` whose SYN gets no answer would sit for the kernel's ~75-second SYN-retransmit budget).
3. Two threads move bytes: the device's raw TLS bytes from the inbound buffer are written into the socket, and the listener's encrypted output is read from the socket and packetized by `writeToDevice`.
4. The listener's decrypted plaintext is handed to the capture view and forwarded to an upstream `NWConnection`. The upstream connects to the **IP the device itself resolved** (no second DNS lookup, no risk of a CDN handing the extension a different edge) while `sec_protocol_options_set_tls_server_name` supplies the real hostname from the ClientHello, so SNI and certificate hostname validation both use the right name.

Every wait in this pipeline is bounded (5 seconds for listener-ready and accept, 10 seconds for upstream) because Network.framework surfaces establishment-time failures as `.waiting`, not `.failed`, and `.waiting` never signals anything. An unbounded wait left sessions parked forever and the device staring at a connection that never answered.

#### Minting leaf certificates

`LeafCertCache.identity(for:)` creates a P-256 key pair per SNI and asks `X509CertBuilder.buildLeafCert` for a certificate whose issuer field is the CA certificate's subject, byte for byte. That is how the device's chain builder finds the installed CA; anything else fails with `errSecCreateChainFailed`.

Two things learned on hardware are enforced in code:

- Only the **private** half of the leaf key pair is persisted to the keychain. Passing `kSecAttrIsPermanent` at the top level of `SecKeyCreateRandomKey` persists both halves under the same application tag, and the identity lookup then sometimes returned the public key as if it were the signing key. The symptom was Network.framework aborting the handshake with `-9858` while the connection was still `.preparing`, with no ServerHello ever sent.
- Before an identity is cached, `verifyUsable` checks that its certificate is byte-for-byte the leaf just minted and that its private key can produce the ECDSA-SHA256 signature the handshake will ask for. A failure is recorded in Settings with the detail instead of surfacing as a generic dropped connection.

The cache holds up to 200 domains and deletes the evicted domain's keychain items; `purge()` runs when the tunnel stops.

### Diagnostics: What to Look at When It Doesn't Work

Console access to a running network extension on a real iPhone has been unreliable enough during development that the extension reports on itself in three places. All of them are intentional and worth keeping.

- **Settings, drop count and "Last:" line.** `SharedSettings.tlsInterceptorDropCount` and `tlsInterceptorLastError` are written by the extension and shown under TLS Inspection in Settings. Every guard in the session runner records *why* it bailed and at which stage (`clientHelloWait`, `identity`, `listenerReadyWait`, `posixConnect`, `acceptWait`, `upstreamConnect`, `deviceTLSHandshake`, `bridged`, `decrypting`), and the bridge phase records whether the upstream ever sent application data. This is debug tooling that ships on purpose, not leftover scaffolding: it is what pinned down the loopback-scoping `ETIMEDOUT` and the FIN-storm investigation. Do not remove it as dead code.
- **Unified log.** `log stream --predicate 'subsystem == "com.mDNSShark.PacketTunnel"'` shows the `forwarder`, `TLSInterceptor`, and `relay` categories. The lines that answer "did the device accept our SYN-ACK" are `sendSYNACK to ...`, the device's first pure ACK, and `first device bytes received ... handshake completed`; `device-facing TLS READY` means the device trusted the leaf, and `first write to device` gives the seq to compare against the device's later ack numbers. Every line is stamped with milliseconds since the session opened.
- **Packet capture.** The Packet Capture view's export writes a `.pcap` that includes the extension's own synthetic packets (SYN-ACK, ServerHello flight, ACKs, FIN), tagged `[reconstructed]`. Until every synthetic packet was routed through the shared `onPacket` hook, captures showed only what the device sent and never what we sent back, which made the oversized-segment and FIN-storm bugs impossible to see from a pcap alone.

The plain relay additionally wraps every flow in an `OSSignposter` interval (`relayFlow`, session open to first reply, or "no reply" on teardown), readable in Instruments' os_signpost template.

### Setting Up TLS Inspection

TLS Inspection requires a CA certificate that iOS trusts as a root. There are two separate halves to this, and the second one is easy to miss: getting the CA into mDNSShark's keychain (so the extension can sign leaves with it), and installing that same CA as a trusted profile in iOS (so Safari and other apps accept those leaves). `Generate CA…` only does the first half. Until the second half is done, `Settings → General → About → Certificate Trust Settings` shows nothing for mDNSShark and every intercepted connection fails the device-facing handshake.

The Settings screen offers three ways to get a CA:

| Option                 | When to use                                                   |
| ---------------------- | ------------------------------------------------------------- |
| **Import from Files…** | You have an existing `.cer`, `.pem`, or `.p12` / `.pfx` file  |
| **Paste PEM / P12…**   | You want to paste raw PEM certificate and/or private key text |
| **Generate CA…**       | You want mDNSShark to create a new CA key pair on-device      |

`Generate CA…` creates a P-256 key pair, builds a self-signed CA (`CN=mDNSShark CA`, valid three years), stores both in the keychain access group, and exports the certificate as `mDNSShark-CA.cer` through the share sheet. If you import or paste a CA instead, make sure it includes the **private key**; a certificate on its own cannot sign leaves.

**Installing and trusting the CA (the manual part):**

1. In mDNSShark, go to **Settings → TLS Inspection** and tap **Generate CA…**. A share sheet appears with `mDNSShark-CA.cer`.
2. In the share sheet, choose **Save to Files** and pick a location.
3. Open the **Files** app and tap the saved `mDNSShark-CA.cer`. iOS shows a "Profile Downloaded" banner.
4. Go to iOS **Settings → General → VPN & Device Management**, tap the mDNSShark CA profile, and tap **Install**.
5. Go to iOS **Settings → General → About → Certificate Trust Settings** and turn on **Enable Full Trust for Root Certificates** for the mDNSShark CA.
6. Return to mDNSShark Settings and toggle **Enable TLS Inspection** on. Only now does the device-facing handshake succeed.

A warning sheet is shown the first time you enable the feature to confirm you understand the implications.

The iOS trust profile is independent of the app and stays installed across rebuilds and reinstalls. If Settings shows "No certificate installed" after a reinstall, generate or import again and repeat from step 3 with the new `.cer`, since a freshly generated CA is a different certificate and the old profile will not trust its leaves.

### TLS Bypass List

Not all apps tolerate a TLS proxy - apps that use certificate pinning (banking, health, government) will fail to connect if intercepted. Add those domains to the **TLS Bypass List** in Settings:

- Enter a domain suffix (e.g. `bank.com`) and tap **+**.
- Any connection whose SNI ends with a listed suffix is passed through uninspected.
- Delete entries with a swipe-left gesture.

Pre-populate the bypass list with any certificate-pinned apps before enabling inspection.

**Always add Apple's own services.** `push.apple.com` (APNs), `icloud.com` (including Private Relay), and `apple-native-relay.apple.com` (Private Relay's egress endpoint) are certificate-pinned and can never be intercepted — their handshakes are specifically designed to resist MITM re-encryption (ECH/QUIC-based), not a bug in `TLSInterceptor.swift`. Without these three entries, their failed sessions show up as a steady stream of drops in the Settings diagnostics (`apple-native-relay.apple.com` fails with `-9830: errSSLIllegalParam`) and bury the errors you actually care about. The bypass list is stored in the shared `UserDefaults` suite and **can be cleared by a rebuild or reinstall**, so re-add all three after a fresh install before reading the drop count as a signal.

### DNS Server

The PacketTunnel extension uses configurable upstream DNS resolvers. Two servers can be set (primary and secondary). Quick-select chips for common providers (Cloudflare `1.1.1.1`, Quad9 `9.9.9.9`, Google `8.8.8.8`) are available in Settings. Changes take effect on the next tunnel restart.

### Capture Filters

The **Capture Filters** section in Settings lets you choose which protocol families are displayed in the packet capture view. Supported protocol labels: `DNS`, `mDNS`, `HTTPS`, `HTTP`, `TCP`, `UDP`, `ICMP`. All are enabled by default; toggle any off to reduce noise.

### Shared Settings (App Group)

All TLS settings are stored in a shared `UserDefaults` suite (`group.beta.mDNSShark`) so the main app and the PacketTunnel extension read the same configuration without IPC overhead. The relevant keys are:

| Key                       | Type            | Default       |
| ------------------------- | --------------- | ------------- |
| `tlsInspectionEnabled`    | Bool            | `false`       |
| `tlsInspectionUnlocked`   | Bool            | `false`       |
| `tlsTrialStartDate`       | Date?           | `nil`         |
| `tlsBypassList`           | JSON `[String]` | `[]`          |
| `dnsPrimary`              | String          | `8.8.8.8`     |
| `dnsSecondary`            | String          | `8.8.4.4`     |
| `captureFilterProtocols`  | JSON `[String]` | all protocols |
| `tlsInterceptorDropCount` | Int             | `0`           |
| `tlsInterceptorLastError` | String          | `""`          |

`tlsInspectionUnlocked` and `tlsTrialStartDate` are written by `PurchaseManager` (main app process, backed by StoreKit) and read by the PacketTunnel extension, which has no StoreKit access of its own. The extension re-checks the unlock state on its 60-second cleanup tick, so a trial expiring or a refund while the tunnel is running turns interception off without a restart.

`tlsInterceptorDropCount` and `tlsInterceptorLastError` flow the other way: written by the extension, read by Settings. They are the diagnostic channel described in [Diagnostics](#diagnostics-what-to-look-at-when-it-doesnt-work) and are meant to stay.

### Certificate Storage

CA and leaf certificate material is stored in the iOS Keychain under the shared access group `group.beta.mDNSShark`:

| Item                              | Keychain class                            |
| --------------------------------- | ----------------------------------------- |
| CA certificate (`SecCertificate`) | `kSecClassCertificate`                    |
| CA private key (`SecKey`)         | `kSecClassKey`                            |
| Per-domain leaf private keys      | `kSecClassKey` (tag `mdns.leaf.<domain>`) |
| Per-domain leaf certificates      | `kSecClassCertificate`                    |

Tapping **Remove Certificate** in Settings purges all CA items and disables inspection. Stopping the tunnel calls `LeafCertCache.purge()` which deletes all in-flight leaf items.

## Where Things Live

A short map for anyone opening the project for the first time:

| Path | What it is |
| ---- | ---------- |
| `PacketTunnel/PacketTunnelProvider.swift` | The `NEPacketTunnelProvider`. Sets up the tunnel, runs the read loop, writes the JSON packet log and the `.pcap` into the App Group container. |
| `PacketTunnel/PacketForwarder.swift` | Routes every outbound packet: plain UDP/TCP relay, hand-off of 443 flows to the interceptor, DNS response caching, QUIC drop. |
| `PacketTunnel/TLSInterceptor.swift` | `parseSNI`, `LeafCertCache`, `TLSSession` (the userspace TCP peer plus TLS bridge), and the `TLSInterceptor` session table. |
| `PacketTunnel/ChecksumHelpers.swift` | RFC 1071 checksum shared by both packet builders. |
| `PacketTunnel/PCAPWriter.swift` | pcap file writer. |
| `mDNSShark/Shared/X509CertBuilder.swift` | Hand-rolled DER encoder for the self-signed CA and the per-domain leaf certificates. |
| `mDNSShark/Shared/KeychainStore.swift` | All keychain access for CA and leaf material, scoped to the App Group access group. |
| `mDNSShark/Shared/SharedSettings.swift` | The shared `UserDefaults` suite in the table above. |
| `mDNSShark/Settings/SettingsView.swift` | TLS Inspection setup UI, CA generation and import, bypass list, diagnostics display. |
| `mDNSShark/Discovery/` | Device enrichment probes (Ubiquiti, ASUS, NetBIOS, JNAP/HNAP, Google Wifi, SSDP description, TTL, ARP table) and their coordinator. |
| `mDNSShark/Security/` | Security tab: `ThreatDatabase` (KEV/NVD loading, refresh, vendor matching), `ThreatCacheStore` (persisted refresh cache), `SecurityViewModel` (port, Bonjour, and vendor-advisory rules), and the findings UI. |
| `mDNSShark/Resources/nist_cpe_map.json` | The curated vendor table (`vendorAdvisories`): manufacturer aliases, KEV `vendorProject` names, NVD search terms, and CPE vendor allowlists. |
| `mDNSShark/Resources/cisa_kev_snapshot.json` | Bundled subset of the CISA KEV catalog, regenerated by `scripts/update_kev_snapshot.py`. |
| `mDNSSharkTests/` | Unit tests for the threat-data and Security tab logic, run with Product → Test in Xcode. |
| `Packages/DeviceFingerprint/` | Pure, unit-tested packet encoders/decoders and merge rules the probes are built on. No networking, no Foundation bundle access. |
| `todo.md` | The working backlog, including the open findings summarized above. |

## System Requirements

1. **Device**: iPhone only.
2. **iOS Version**: **iOS 18.2 or later**, for both the main app and TLS Inspection's `PacketTunnel` extension.
3. **Network**: A reliable Wi-Fi connection is recommended for full scanning capabilities.
4. **Development (Optional)**: To build or modify the code, you'll need a recent **Xcode** (verified with Xcode 26.5). TLS Inspection cannot be exercised in the Simulator; the packet-tunnel extension and the CA trust flow both need a real device.

## Future Enhancements

A rough look at what's next, roughly in priority order:

- **Per-device vulnerability matching.** Security findings for a device's
  manufacturer are vendor-level today. Matching the exact software versions
  some devices already report during a port scan (SSH and HTTP banners,
  for example) against NVD's product data would say whether this specific
  device is affected, not just its vendor.
- **Better identification for GL.iNet routers**, moving from a page-content
  match to GL.iNet's own device API for a more durable signal.
- **ASUS / AiMesh device identification.** The detection logic is already
  built and tested, and Apple has approved the networking permission it
  needs; what remains is enabling it in the build and verifying on a real
  device.
- **Netgear Orbi mesh support** - identifying satellite nodes alongside the
  primary router, not just the primary router itself.

None of these are promises with dates attached - just where our attention
is headed next. If one of them is exactly the itch you want to scratch,
see [Contribute and Collaborate](#contribute-and-collaborate) below.

## Contribute and Collaborate

We're always eager for fresh ideas and extra sets of eyes on the code:

- **Open Issues**: Let us know if you spot bugs or would like a new feature.
- **Pull Requests**: Share your improvements or experiments with the community.
- **Discussions**: Suggest changes, ask questions, or explore new scanning methods.
- **Code Comments**: Reading through a feature and found a rough edge, a clever trick worth explaining, or a "why is this here" moment? Drop a comment on the PR or open an issue - annotating existing code is a great low-friction way to contribute even before you touch a single line.

Every feature in this app - TLS Inspection included - started as someone's idea in an issue or a PR. You don't need to be a Swift expert to contribute: reporting a confusing UI flow, testing on a device we don't have, or just asking "why does this work this way?" all move the project forward.

mDNSShark is grounded in the principle that local network exploration doesn't have to be intimidating - or invasive. We're building a community-driven tool that emphasizes clarity, privacy, and inclusivity, so anyone can understand and troubleshoot what's happening on their own network. Whether you're an experienced developer or just love tinkering, mDNSShark can use your passion and expertise.

Join us to help shape the future of straightforward, on-device network discovery - **no data collection, no lengthy setups, just powerful scanning for everyone.**
