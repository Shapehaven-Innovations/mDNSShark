# Device Fingerprinting — Phase 2 Backlog

## Blocked: multicast entitlement (ASUS probe)

ASUS `infosvr` probe (`Packages/DeviceFingerprint/Sources/DeviceFingerprint/ASUSDiscoveryPacket.swift`,
`mDNSShark/Discovery/ASUSDiscoveryProbe.swift`) is code-complete, tested (83/83
package suite), and reviewed clean. It cannot receive real replies until the
`com.apple.developer.networking.multicast` entitlement is approved — ASUS's
reply is a UDP broadcast, which iOS won't deliver without it.

- **Apple approval request submitted 2026-09-20 — Request ID: V6723AP975.**
  Timeline unknown; check status at developer.apple.com.
- Once approved, still need to: (1) enable the capability for this App ID in
  the Developer Portal, (2) regenerate the provisioning profile so Xcode
  picks it up, (3) rebuild and test on a real device (not Simulator — this
  Mac can't run vphone-cli either, it's Intel not Apple Silicon).
- Entitlement is already added to both `mDNSShark/mDNSShark.entitlements` and
  `mDNSShark/mDNSSharkDebug.entitlements` (`<true/>`, verified correct format
  against Apple's own docs) — no further code change needed once approval
  and the profile regen land.
- Until then: HTTP banner grab and the mDNS extension (Google Cast/HomeKit)
  work in any build today, no entitlement needed — safe to test those now.


Follow-up items from the vendor-protocol research pass (2026-09-19/20), after the
first three (ASUS `infosvr` probe, active HTTP banner grab, mDNS extension for
Google Cast / HomeKit) are built. Ordered by priority (value-per-effort, per
fable's research synthesis). Each item fits the existing architecture unless
noted otherwise: a pure codec + test in `Packages/DeviceFingerprint`, a thin
socket-I/O wrapper in `mDNSShark/Discovery/`, wired into
`DeviceEnrichmentCoordinator` behind the shared `ProbeConcurrencyLimiter` (and
`UDPSendPacer` if UDP), with a new `EnrichmentSource` case in
`DeviceEnrichment.swift`.

## 1. HNAP + Linksys JNAP (Linksys, some D-Link)

- **Signal:** `POST /HNAP1/` (SOAP, `GetDeviceSettings` action) or
  `POST /JNAP/` (JSON, `X-JNAP-Action` header) → VendorName/ModelDescription/
  ModelName/FirmwareVersion directly. HNAP covers older Linksys + some D-Link;
  JNAP covers newer Linksys (Velop mesh included).
- **Effort:** small — same shape as the already-built SSDP-description
  fetcher (one HTTP POST, parse a structured response). Combine both into one
  probe that tries JNAP first, falls back to HNAP, since both target the same
  vendor family and firing both at every host doubles traffic for no reason.
- **Gate on:** an existing OUI/SSDP-manufacturer hint suggesting Linksys/
  D-Link first, rather than firing at every host — keeps per-host request
  count flat as more vendor-specific probes get added over time.
- **Own session:** no — same size/shape as the three items already shipped
  this pass, fits a similar single-session dispatch.

## 2. Google Wifi `/api/v1/status`

- **Signal:** unauthenticated `GET http://<ip>/api/v1/status` (port 80) →
  hardware id, software version, model. Definitive Google/Nest Wifi
  identification.
- **Effort:** small — literally a plain HTTP GET, no auth, no SOAP/JSON
  envelope to construct.
- **Gate on:** the `_googlecast._tcp` mDNS hit from item 3 of the first
  batch (only fire this active probe against hosts mDNS already flagged as
  Google Cast-capable, to avoid probing every host on the LAN speculatively).
- **Own session:** no.

## 3. Verify MAC-OUI coverage for mesh vendors (no new probe — testing only)

- **Signal:** none new — the app already bundles the full IEEE OUI table.
  eero, Google, Netgear, Linksys, TP-Link, ASUS should already resolve to a
  manufacturer *whenever the app obtains a MAC* for one of their devices via
  an existing path (NetBIOS reply, or a future probe).
- **Effort:** small, verification-only — add a package-level test asserting
  known OUI prefixes for these vendors resolve correctly via `OUIDataset`,
  and do a real on-device check once item 1/2 above exist and can surface a
  MAC for a Linksys/Google device to confirm end-to-end.
- **Own session:** no — can piggyback on whichever item above ships next.

## 4. Netgear Orbi `GetAllSatellites` (router-side SOAP)

- **Signal:** SOAP call to the PRIMARY Orbi router lists its satellite
  nodes' info.
- **Effort:** medium. **Architectural mismatch, not just implementation
  weight:** this call reports OTHER hosts' identity (the satellites), not
  the queried host's own identity — the current `DeviceEnrichment`/`merge()`
  model has no concept of one host's probe result attributing data to a
  DIFFERENT host. Needs either an extension to that model (a per-batch
  "applies to IP X, not the responding IP" field) or a separate topology-
  layer feature entirely.
- **Own session: yes** — this needs a real design decision before any code,
  not just a new probe file. Brainstorm/design first, likely its own
  bounded (or larger) planning pass.

## 5. TR-064 (some ISP gateways — AT&T/Spectrum unconfirmed)

- **Signal:** LAN-side SOAP configuration protocol, UPnP-extension.
- **Effort:** small if a target device is confirmed to implement it — same
  shape as HNAP/JNAP.
- **Blocker:** no confirmed AT&T or Spectrum gateway model implementing
  this was found during research. Building a speculative probe against
  every gateway is traffic spent with no evidence of payoff, and conflicts
  with this app's anti-flood discipline (every existing probe fires only
  where there's a real reason to expect a reply).
- **Do not build** until a specific real target device/model is confirmed.
  If a customer support report or your own hardware confirms a TR-064-
  speaking gateway, revisit — small effort once a target exists.
- **Own session:** n/a until unblocked.

## 6. TP-Link Deco (OneMesh, UDP 20002)

- **Signal:** broadcast probe (type `0xF8`), but the reply payload is
  **AES-128 encrypted with a hardcoded key** — the mechanism is real and
  documented (Fox-IT's MeshyJSON research, community PoCs) but requires
  implementing decryption correctly in the pure-codec layer, a first for
  this codebase's protocol handlers.
- **Effort:** medium-large. New category of risk: a crypto bug is a
  different failure mode than the wire-format-offset bugs already caught
  and fixed in this codebase's history (RFC 1002 NetBIOS offset, IP_TTL vs
  IP_RECVTTL) — decryption either works or produces silent garbage, worth
  extra scrutiny if built.
- **Own session: yes** — real new capability (crypto in the pure-codec
  layer), deserves its own brainstorm + design pass, not a quick add-on.
  Only worth doing if Deco users are a measurable share of the target
  audience — worth asking whether that's true before investing here.

## 7. Starlink local gRPC API (`192.168.100.1:9200`)

- **Signal:** `get_status` → `device_info` (hardware/software version, unit
  ID). Well-documented via community tooling (`starlink-grpc-tools`,
  `starlink-rs`).
- **Effort: large.** iOS/Swift has no built-in gRPC support — this needs a
  third-party dependency (a real new build-system/dependency-management
  decision, this codebase currently has zero external Swift package
  dependencies) or hand-rolling protobuf framing over HTTP/2 from scratch.
  Also architecturally different from every other probe here: it's a
  single fixed well-known address, not a per-host signal fanned out across
  the subnet — doesn't fit the existing `DeviceEnrichmentCoordinator`
  per-IP model at all, would need its own special-cased "is there a
  Starlink gateway on this network" check run once per scan, not per host.
- **Own session: yes, and a bigger one** — new dependency decision, new
  architecture shape (once-per-scan special case, not per-host), a
  from-scratch gRPC/protobuf client. This is the single biggest item on
  this list. Only build if you specifically want Starlink support — skip
  otherwise, since the return (one device, on Starlink-only networks) is
  narrow relative to the investment.

## Not on this list — confirmed dead end, don't revisit

**Wi-Fi EasyMesh / IEEE 1905.1** — runs directly over Ethernet Layer 2 (no
IP stack), structurally unreachable from a sandboxed iOS app under any
circumstances, and none of the researched mesh vendors (eero, Google Nest,
Orbi, Velop, Deco) are even EasyMesh-certified — all proprietary. No
cross-vendor payoff exists here even in principle. Closed.
