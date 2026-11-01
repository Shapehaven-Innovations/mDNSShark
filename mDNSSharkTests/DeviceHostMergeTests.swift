// mDNSSharkTests/DeviceHostMergeTests.swift
import Testing
import Foundation
import DeviceFingerprint
@testable import mDNSShark

@MainActor
@Suite("Bonjour services attach to their host; unresolved ones stay services")
struct DeviceHostMergeTests {

    // Own addresses are injected as empty and probes are swallowed, so no test depends on the host's interfaces or sends traffic.
    private func viewModel() -> NetworkScanViewModel {
        NetworkScanViewModel(ownAddresses: { [] }, probe: { _, _ in })
    }

    // TEST-NET-3 and documentation-range addresses: the enrichment coordinator refuses them, so merge() fires no probes.
    // Rows are born settled, as a resolve that answered would leave them; pending-resolve tests clear the flag explicitly.
    private func bonjourRow(type: String, name: String, ip: String?, host: String?, port: Int = 80) -> NetworkScanner.Device {
        let row = NetworkScanner.Device(serviceName: name, serviceDomain: "local.", serviceType: type)
        row.resolvedIPAddress = ip
        row.hostName = host
        row.port = port
        row.resolveSettled = true
        return row
    }

    private func sweepRow(_ ip: String) -> NetworkScanner.Device {
        let row = NetworkScanner.Device(serviceName: ip, serviceDomain: "local", serviceType: "tcp")
        row.resolvedIPAddress = ip
        row.resolveSettled = true
        return row
    }

    private func ports(_ ports: [Int]) -> DeviceEnrichment {
        DeviceEnrichment(mac: nil, manufacturer: nil, inferredOS: nil, openPorts: ports, source: .portBanner)
    }

    // MARK: - Ingest normalisation

    @Test("Device.hostKey lowercases and strips one trailing dot, leaving hostName for display")
    func hostKeyNormalisedAtIngest() {
        let row = bonjourRow(type: "_ssh._tcp", name: "Mac", ip: nil, host: "Mac.LOCAL.")
        #expect(row.hostKey == "mac.local")
        #expect(row.hostName == "Mac.LOCAL.")
        row.hostName = "mac.local"
        #expect(row.hostKey == "mac.local")
        row.hostName = nil
        #expect(row.hostKey == nil)
        row.hostName = "."
        #expect(row.hostKey == nil)
    }

    @Test("Device.serviceTypeKey strips one trailing dot once at ingest, leaving serviceType for display")
    func serviceTypeKeySetAtIngest() {
        let dotted = NetworkScanner.Device(serviceName: "x", serviceDomain: "local.", serviceType: "_http._tcp.")
        let plain = NetworkScanner.Device(serviceName: "x", serviceDomain: "local.", serviceType: "_http._tcp")
        #expect(dotted.serviceTypeKey == "_http._tcp" && dotted.serviceType == "_http._tcp.")
        #expect(plain.serviceTypeKey == "_http._tcp" && plain.serviceType == "_http._tcp")
    }

    @Test("IP literals are told apart from DNS names")
    func ipLiteralDetection() {
        #expect(NetworkScanner.isIPAddressLiteral("192.168.1.10"))
        #expect(NetworkScanner.isIPAddressLiteral("2001:db8::1"))
        #expect(NetworkScanner.isIPAddressLiteral("fe80::1%en0"))
        #expect(!NetworkScanner.isIPAddressLiteral("Mac.local."))
        #expect(!NetworkScanner.isIPAddressLiteral("tv.example.com"))
    }

    // MARK: - Merging by host

    @Test("a service that resolved to the host's link-local IPv4 merges into the host's LAN row")
    func linkLocalServiceMergesIntoHost() {
        let vm = viewModel()
        let lan = bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)
        let burst = bonjourRow(type: "_http._tcp", name: "burst150", ip: "169.254.46.247", host: "Mac.local.", port: 8150)

        let devices = vm.merge(raw: [lan, burst])

        #expect(devices.count == 1)
        #expect(devices[0].ipAddress == "203.0.113.10")
        #expect(Set(devices[0].bonjourServices.map(\.serviceType)) == ["_ssh._tcp", "_http._tcp"])
    }

    @Test("the LAN address wins even when the link-local row arrives first")
    func linkLocalRowFirstStillKeysByLANAddress() {
        let vm = viewModel()
        let burst = bonjourRow(type: "_http._tcp", name: "burst150", ip: "169.254.46.247", host: "Mac.local.", port: 8150)
        let lan = bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)

        let devices = vm.merge(raw: [burst, lan])

        #expect(devices.count == 1)
        #expect(devices[0].ipAddress == "203.0.113.10")
    }

    @Test("an IPv6-only row still collapses onto the host's IPv4 row")
    func ipv6RowCollapsesOntoIPv4() {
        let vm = viewModel()
        let airplay = bonjourRow(type: "_airplay._tcp", name: "Apple TV", ip: "2001:db8::7", host: "Apple-TV.local.", port: 7000)
        let raop = bonjourRow(type: "_raop._tcp", name: "AABB@Apple TV", ip: "203.0.113.7", host: "Apple-TV.local.", port: 7000)

        let devices = vm.merge(raw: [airplay, raop])

        #expect(devices.count == 1)
        #expect(devices[0].ipAddress == "203.0.113.7")
        #expect(devices[0].bonjourServices.count == 2)
    }

    @Test("a host with only IPv6 addresses keeps one IPv6 row, as the phone itself does")
    func ipv6OnlyHostKeepsOneRow() {
        let vm = viewModel()
        let rdlink = bonjourRow(type: "_rdlink._tcp", name: "iPhone", ip: "2001:db8::1", host: "iPhone.local.", port: 49152)
        let companion = bonjourRow(type: "_companion-link._tcp", name: "iPhone", ip: "2001:db8::1", host: "iPhone.local.", port: 49153)

        let devices = vm.merge(raw: [rdlink, companion])

        #expect(devices.count == 1)
        #expect(devices[0].ipAddress == "2001:db8::1")
        #expect(devices[0].bonjourServices.count == 2)
    }

    @Test("rows without a Bonjour host name still key by their own address")
    func rowsWithoutHostNameKeyByIP() {
        let vm = viewModel()
        let sweep = NetworkScanner.Device(serviceName: "203.0.113.30", serviceDomain: "local", serviceType: "tcp")
        sweep.resolvedIPAddress = "203.0.113.30"
        let ssdp = NetworkScanner.Device(serviceName: "uuid:tv", serviceDomain: "ssdp", serviceType: "ssdp")
        ssdp.resolvedIPAddress = "203.0.113.31"

        let devices = vm.merge(raw: [sweep, ssdp])

        #expect(devices.map(\.ipAddress) == ["203.0.113.30", "203.0.113.31"])
    }

    @Test("host names differing only in case or trailing dot merge into one device")
    func hostNameCaseAndTrailingDotMerge() {
        let vm = viewModel()
        let upper = bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)
        let lower = bonjourRow(type: "_http._tcp", name: "burst150", ip: "169.254.46.247", host: "mac.local", port: 8150)

        let devices = vm.merge(raw: [upper, lower])

        #expect(devices.count == 1)
        #expect(devices[0].ipAddress == "203.0.113.10")
        #expect(Set(devices[0].bonjourServices.map(\.serviceType)) == ["_ssh._tcp", "_http._tcp"])
    }

    @Test("the merged row shows the raw Bonjour host name as received, not whichever service was processed first")
    func mergedRowNamedAfterHostInEitherOrder() {
        let airplay = bonjourRow(type: "_airplay._tcp", name: "Living Room", ip: "2001:db8::7", host: "Apple-TV.local.", port: 7000)
        let raop = bonjourRow(type: "_raop._tcp", name: "AABB@Living Room", ip: "203.0.113.7", host: "Apple-TV.local.", port: 7000)

        let forward = viewModel().merge(raw: [airplay, raop])
        let reversed = viewModel().merge(raw: [raop, airplay])

        #expect(forward.map(\.hostname) == ["Apple-TV.local."])
        #expect(reversed.map(\.hostname) == ["Apple-TV.local."])
    }

    @Test("rows at one address with differently spelled host names pick the lexicographically smallest raw name in either order")
    func differentlySpelledHostNamesPickSmallestRaw() {
        let upper = bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)
        let lower = bonjourRow(type: "_http._tcp", name: "Mac", ip: "203.0.113.10", host: "mac.local", port: 80)

        let forward = viewModel().merge(raw: [upper, lower])
        let reversed = viewModel().merge(raw: [lower, upper])

        #expect(forward.map(\.hostname) == ["Mac.local."])
        #expect(reversed.map(\.hostname) == ["Mac.local."])
    }

    @Test("a service entry keeps its type exactly as received; only its id drops the trailing dot")
    func serviceTypeStaysRawInEntries() {
        let vm = viewModel()
        let orphan = bonjourRow(type: "_http._tcp.", name: "orphan", ip: nil, host: nil, port: 8080)

        let result = vm.mergeScan(raw: [orphan])

        #expect(result.services.map(\.serviceType) == ["_http._tcp."])
        #expect(result.services.map(\.typeLabel) == ["_http._tcp."])
        #expect(result.services.map(\.id) == ["_http._tcp|orphan|local."])
    }

    @Test("an SSDP device with no host name shows its UPnP friendly name once it arrives, never the SERVER header or the USN")
    func ssdpDeviceNameComesFromTheDescription() {
        let vm = viewModel()
        let ssdp = NetworkScanner.Device(serviceName: "uuid:tv", serviceDomain: "ssdp", serviceType: "ssdp")
        ssdp.resolvedIPAddress = "203.0.113.31"
        ssdp.ssdpServer = "Linux/4.x UPnP/1.0 Product/1.0"

        // Before the description answers: the address, with the header kept as a literal field.
        let before = vm.merge(raw: [ssdp])
        #expect(before.map(\.hostname) == ["203.0.113.31"])
        #expect(before.first?.ssdpServer == "Linux/4.x UPnP/1.0 Product/1.0")

        vm.ingestEnrichment(ip: "203.0.113.31", enrichments: [], completesProbeSet: false, upnpName: "Living Room TV")
        let after = vm.merge(raw: [ssdp])
        #expect(after.map(\.hostname) == ["Living Room TV"])
        #expect(after.map(\.id) == before.map(\.id))
    }

    @Test("two LAN IPv4 addresses on one host key the same IP in either order")
    func twoLANAddressesKeySameIPInEitherOrder() {
        let printer = bonjourRow(type: "_ipp._tcp", name: "Printer", ip: "203.0.113.42", host: "Printer.local.", port: 631)
        let web = bonjourRow(type: "_http._tcp", name: "Printer", ip: "203.0.113.9", host: "Printer.local.", port: 80)

        let forward = viewModel().merge(raw: [printer, web])
        let reversed = viewModel().merge(raw: [web, printer])

        #expect(forward.map(\.ipAddress) == ["203.0.113.9"])
        #expect(reversed.map(\.ipAddress) == ["203.0.113.9"])
        #expect(forward[0].bonjourServices.count == 2 && reversed[0].bonjourServices.count == 2)
    }

    // MARK: - Identity

    @Test("re-merging with the rows in reverse order keeps the device's UUID")
    func reversedOrderKeepsStableID() {
        let vm = viewModel()
        let lan = bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)
        let burst = bonjourRow(type: "_http._tcp", name: "burst150", ip: "169.254.46.247", host: "Mac.local.", port: 8150)

        let first = vm.merge(raw: [lan, burst])
        let second = vm.merge(raw: [burst, lan])

        #expect(first.count == 1 && second.count == 1)
        #expect(first[0].id == second[0].id)
    }

    @Test("a host keeps its UUID when its chosen address changes")
    func identityStableAcrossAddressFlip() {
        let vm = viewModel()
        let before = vm.merge(raw: [bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "169.254.46.247", host: "Mac.local.", port: 22)])
        // The LAN address shows up on a later pass and becomes the preferred one.
        let after = vm.merge(raw: [
            bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "169.254.46.247", host: "Mac.local.", port: 22),
            bonjourRow(type: "_http._tcp", name: "Mac", ip: "203.0.113.10", host: "mac.local", port: 80)
        ])

        #expect(before[0].ipAddress == "169.254.46.247")
        #expect(after[0].ipAddress == "203.0.113.10")
        #expect(before[0].id == after[0].id)
    }

    @Test("one host on two addresses is one device with one UUID")
    func oneHostTwoAddressesOneDevice() {
        let vm = viewModel()
        let a = bonjourRow(type: "_ipp._tcp", name: "Printer", ip: "203.0.113.42", host: "Printer.local.", port: 631)
        let b = bonjourRow(type: "_http._tcp", name: "Printer", ip: "203.0.113.9", host: "Printer.local.", port: 80)

        let devices = vm.merge(raw: [a, b])
        let again = vm.merge(raw: [b, a])

        #expect(devices.count == 1)
        #expect(again.map(\.id) == devices.map(\.id))
    }

    @Test("two different hosts never share a UUID")
    func differentHostsGetDifferentIDs() {
        let vm = viewModel()
        let one = bonjourRow(type: "_ssh._tcp", name: "a", ip: "203.0.113.10", host: "a.local.", port: 22)
        let two = bonjourRow(type: "_ssh._tcp", name: "b", ip: "203.0.113.11", host: "b.local.", port: 22)

        let devices = vm.merge(raw: [one, two])

        #expect(devices.count == 2)
        #expect(devices[0].id != devices[1].id)
    }

    @Test("a device first seen by address keeps its UUID once its host name is learned")
    func addressOnlyDeviceKeepsIDWhenHostKeyArrives() {
        let vm = viewModel()
        let sweep = NetworkScanner.Device(serviceName: "203.0.113.10", serviceDomain: "local", serviceType: "tcp")
        sweep.resolvedIPAddress = "203.0.113.10"
        let before = vm.merge(raw: [sweep])
        let after = vm.merge(raw: [sweep, bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)])

        #expect(after.count == 1)
        #expect(before[0].id == after[0].id)
    }

    @Test("a host key learned last scan keeps its UUID when the address-only row arrives first in the next scan")
    func hostKeyLearnedLastScanKeepsUUIDWhenAddressRowArrivesFirst() {
        let vm = viewModel()
        let mac = bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)
        let first = vm.merge(raw: [mac])

        vm.resetForNewScan()
        let sweepOnly = vm.merge(raw: [sweepRow("203.0.113.10")])
        let withHost = vm.merge(raw: [sweepRow("203.0.113.10"), mac])

        #expect(sweepOnly.count == 1 && withHost.count == 1)
        #expect(sweepOnly[0].id == first[0].id)
        #expect(withHost[0].id == first[0].id)
    }

    @Test("a host key seen this merge beats the identity remembered for a reassigned address")
    func currentHostKeyBeatsRememberedIdentity() {
        let vm = viewModel()
        let old = vm.merge(raw: [bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)])

        vm.resetForNewScan()
        let moved = vm.merge(raw: [bonjourRow(type: "_ipp._tcp", name: "Printer", ip: "203.0.113.10", host: "Printer.local.", port: 631)])

        #expect(moved.count == 1)
        #expect(moved[0].id != old[0].id)
        #expect(moved[0].hostname == "Printer.local.")
    }

    // MARK: - Identity memory expiry

    @Test("a remembered host identity still applies to an address-only row after two scans without it, and after a refresh")
    func rememberedIdentitySurvivesWhileRefreshed() {
        let vm = viewModel()
        let mac = vm.merge(raw: [bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)])

        for _ in 1...3 { vm.resetForNewScan() }
        let inherited = vm.merge(raw: [sweepRow("203.0.113.10")])
        #expect(inherited.map(\.id) == mac.map(\.id))

        // The inheriting merge refreshed the memory, so another three scans later it still applies.
        for _ in 1...3 { vm.resetForNewScan() }
        let again = vm.merge(raw: [sweepRow("203.0.113.10")])
        #expect(again.map(\.id) == mac.map(\.id))
    }

    @Test("a remembered host identity is dropped once its address goes unseen for three whole scans")
    func rememberedIdentityExpiresAfterThreeUnseenScans() {
        let vm = viewModel()
        let mac = vm.merge(raw: [bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)])

        for _ in 1...4 { vm.resetForNewScan() }
        let fresh = vm.merge(raw: [sweepRow("203.0.113.10")])

        #expect(fresh.count == 1)
        #expect(fresh[0].id != mac[0].id)
        #expect(fresh[0].hostname == "203.0.113.10")
    }

    @Test("a recycled address does not inherit the identity of a host that moved away long ago, while that host keeps its own UUID")
    func recycledAddressDoesNotInheritExpiredHost() {
        let vm = viewModel()
        let atOld = vm.merge(raw: [bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)])
        let moved = bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.11", host: "Mac.local.", port: 22)

        // Four scans see the Mac on its new address only, so the old address's memory ages out.
        for _ in 1...4 {
            vm.resetForNewScan()
            _ = vm.merge(raw: [moved])
        }
        // The Mac's host key is unclaimed in this merge, so only the expiry stops the sweep row from inheriting it.
        let recycled = vm.merge(raw: [sweepRow("203.0.113.10")])
        #expect(recycled.count == 1)
        #expect(recycled[0].id != atOld[0].id)
        #expect(recycled[0].hostname == "203.0.113.10")

        let macAgain = vm.merge(raw: [moved])
        #expect(macAgain.map(\.id) == atOld.map(\.id))
    }

    // MARK: - plan(): the pure merge

    private var noMemory: [String: String] { [:] }

    @Test("plan is independent of row order in its grouping, identity and names; only the per-row addresses follow the input order")
    func planIsOrderIndependent() {
        let rows = [
            bonjourRow(type: "_airplay._tcp", name: "Living Room", ip: "2001:db8::7", host: "Apple-TV.local.", port: 7000),
            bonjourRow(type: "_raop._tcp", name: "AABB@Living Room", ip: "203.0.113.7", host: "apple-tv.local", port: 7000),
            bonjourRow(type: "_http._tcp", name: "orphan", ip: nil, host: nil, port: 8080),
            sweepRow("203.0.113.30")
        ]

        let forward = NetworkScanViewModel.plan(raw: rows, own: .none, remembered: noMemory)
        let reversed = NetworkScanViewModel.plan(raw: rows.reversed(), own: .none, remembered: noMemory)

        #expect(forward.effectiveIPByRow == ["203.0.113.7", "203.0.113.7", nil, "203.0.113.30"])
        #expect(reversed.effectiveIPByRow == Array(forward.effectiveIPByRow.reversed()))
        #expect(forward.identityByEffectiveIP == ["203.0.113.7": "apple-tv.local", "203.0.113.30": "203.0.113.30"])
        #expect(forward.addressesByEffectiveIP == ["203.0.113.7": ["203.0.113.7", "2001:db8::7"], "203.0.113.30": ["203.0.113.30"]])
        #expect(forward.hostNameByIP == ["203.0.113.7": "Apple-TV.local."])
        #expect(forward.hostIdentityByAddress == ["203.0.113.7": "apple-tv.local", "2001:db8::7": "apple-tv.local"])
        #expect(reversed.identityByEffectiveIP == forward.identityByEffectiveIP)
        #expect(reversed.addressesByEffectiveIP == forward.addressesByEffectiveIP)
        #expect(reversed.hostNameByIP == forward.hostNameByIP)
        #expect(reversed.hostIdentityByAddress == forward.hostIdentityByAddress)
    }

    @Test("plan folds the phone's rows onto its Wi-Fi IPv4 and lists every own address on that row")
    func planFoldsOwnDevice() {
        let own = LocalInterfaces.OwnAddresses(primary: ["192.168.8.123", "fe80::aaaa%en0"],
                                               all: ["192.168.8.123", "fe80::aaaa%en0", "fe80::cccc%anpi0"])
        let rows = [
            bonjourRow(type: "_rdlink._tcp", name: "iPhone", ip: "fe80::cccc%anpi0", host: "iPhone.local.", port: 49152),
            sweepRow("192.168.8.123"),
            bonjourRow(type: "_rdlink._tcp", name: "iPad", ip: "fe80::bbbb%anpi0", host: "iPad.local.", port: 49152)
        ]

        let plan = NetworkScanViewModel.plan(raw: rows, own: own, remembered: noMemory)

        #expect(plan.effectiveIPByRow == ["192.168.8.123", "192.168.8.123", "fe80::bbbb%anpi0"])
        #expect(plan.identityByEffectiveIP == ["192.168.8.123": "iphone.local", "fe80::bbbb%anpi0": "ipad.local"])
        #expect(plan.addressesByEffectiveIP["192.168.8.123"] == ["192.168.8.123", "fe80::aaaa%en0", "fe80::cccc%anpi0"])
        #expect(plan.addressesByEffectiveIP["fe80::bbbb%anpi0"] == ["fe80::bbbb%anpi0"])
        #expect(plan.hostNameByIP == ["192.168.8.123": "iPhone.local.", "fe80::bbbb%anpi0": "iPad.local."])
    }

    @Test("plan groups a host's addresses under its preferred one and maps each to the host key for the identity memory")
    func planGroupsAddressesByHost() {
        let rows = [
            bonjourRow(type: "_airplay._tcp", name: "Mac", ip: "fe80::1%en0", host: "Mac.local.", port: 7000),
            bonjourRow(type: "_http._tcp", name: "Mac", ip: "169.254.46.247", host: "Mac.local.", port: 80),
            bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22),
            bonjourRow(type: "_http._tcp", name: "burst12", ip: nil, host: "Mac.local.", port: 8012)
        ]

        let plan = NetworkScanViewModel.plan(raw: rows, own: .none, remembered: noMemory)

        #expect(plan.effectiveIPByRow == Array(repeating: "203.0.113.10", count: 4))
        #expect(plan.addressesByEffectiveIP == ["203.0.113.10": ["203.0.113.10", "169.254.46.247", "fe80::1%en0"]])
        #expect(plan.hostIdentityByAddress == ["203.0.113.10": "mac.local", "169.254.46.247": "mac.local", "fe80::1%en0": "mac.local"])
    }

    @Test("plan uses a remembered host key for an address-only group unless a row in this merge already claims it")
    func planUsesRememberedIdentityUnlessClaimed() {
        let remembered = ["203.0.113.10": "mac.local"]

        let inherited = NetworkScanViewModel.plan(raw: [sweepRow("203.0.113.10")], own: .none, remembered: remembered)
        #expect(inherited.identityByEffectiveIP == ["203.0.113.10": "mac.local"])
        #expect(inherited.hostIdentityByAddress == ["203.0.113.10": "mac.local"])

        let claimed = NetworkScanViewModel.plan(
            raw: [sweepRow("203.0.113.10"), bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.11", host: "Mac.local.", port: 22)],
            own: .none, remembered: remembered)
        #expect(claimed.identityByEffectiveIP == ["203.0.113.10": "203.0.113.10", "203.0.113.11": "mac.local"])
        #expect(claimed.hostIdentityByAddress == ["203.0.113.11": "mac.local"])
    }

    @Test("plan leaves an address that is a device row of its own out of another host's identity memory")
    func planKeepsOwnRowAddressOutOfOtherHostMemory() {
        // The host-less sweep row at the Mac's link-local address is its own group, so the Mac's key is not remembered for it.
        let rows = [
            bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22),
            bonjourRow(type: "_http._tcp", name: "Mac", ip: "169.254.46.247", host: "Mac.local.", port: 80),
            sweepRow("169.254.46.247")
        ]

        let plan = NetworkScanViewModel.plan(raw: rows, own: .none, remembered: noMemory)

        #expect(plan.effectiveIPByRow == ["203.0.113.10", "203.0.113.10", "169.254.46.247"])
        #expect(plan.identityByEffectiveIP == ["203.0.113.10": "mac.local", "169.254.46.247": "169.254.46.247"])
        #expect(plan.hostIdentityByAddress == ["203.0.113.10": "mac.local"])
    }

    // MARK: - Enrichment

    @Test("enrichment stored under the probed address survives the device's identity switching from IP to host key")
    func enrichmentSurvivesIdentitySwitch() {
        let vm = viewModel()
        let sweep = sweepRow("203.0.113.10")
        let before = vm.merge(raw: [sweep])
        vm.ingestEnrichment(ip: "203.0.113.10", enrichments: [ports([22])])

        let after = vm.merge(raw: [sweep, bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)])

        #expect(after.count == 1)
        #expect(after[0].id == before[0].id)
        #expect(after[0].openPorts == [22])
    }

    @Test("enrichment probed on a host's second address is gathered onto the host's device")
    func enrichmentOnSecondAddressReachesHost() {
        let vm = viewModel()
        let lan = bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)
        let other = bonjourRow(type: "_http._tcp", name: "Mac", ip: "203.0.113.9", host: "Mac.local.", port: 80)
        _ = vm.merge(raw: [lan, other])
        vm.ingestEnrichment(ip: "203.0.113.10", enrichments: [ports([22])])

        let devices = vm.merge(raw: [lan, other])

        #expect(devices.map(\.ipAddress) == ["203.0.113.9"])
        #expect(devices[0].openPorts == [22])
    }

    @Test("the previous scan's enrichment is carried until this scan's probe of the address answers")
    func enrichmentCarriedAcrossScanUntilFreshResult() {
        // A LAN address is probed, so its carried result is real; a non-LAN address settles at once with no ports.
        let vm = viewModel()
        let sweep = sweepRow("192.168.8.50")
        _ = vm.merge(raw: [sweep])
        vm.ingestEnrichment(ip: "192.168.8.50", enrichments: [ports([22])])

        vm.resetForNewScan()
        let carried = vm.merge(raw: [sweep])
        #expect(carried[0].openPorts == [22])

        vm.ingestEnrichment(ip: "192.168.8.50", enrichments: [ports([80])])
        let fresh = vm.merge(raw: [sweep])
        #expect(fresh[0].openPorts == [80])
    }

    // MARK: - Stable output

    @Test("merging the same rows twice yields equal devices and services")
    func mergeTwiceYieldsEqualResults() {
        let vm = viewModel()
        let rows = [
            bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22),
            bonjourRow(type: "_http._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 80),
            bonjourRow(type: "_http._tcp", name: "orphan", ip: nil, host: nil, port: 8080),
            sweepRow("203.0.113.30")
        ]

        let first = vm.mergeScan(raw: rows)
        let second = vm.mergeScan(raw: rows)

        #expect(first.devices == second.devices)
        #expect(first.services == second.services)
    }

    @Test("a Bonjour service's id is derived from its type and name")
    func bonjourServiceIDIsDeterministic() {
        let a = BonjourService(serviceType: "_http._tcp", serviceName: "Test Service", port: 8080)
        let b = BonjourService(serviceType: "_http._tcp", serviceName: "Test Service", port: 8080)
        let c = BonjourService(serviceType: "_http._tcp", serviceName: "Other", port: 8080)
        #expect(a.id == b.id && a == b)
        #expect(a.id != c.id)
    }

    // MARK: - Several services of one type

    @Test("two services of the same type with different names on one host are both kept")
    func sameTypeDifferentNamesBothKept() {
        let vm = viewModel()
        let test = bonjourRow(type: "_http._tcp", name: "Test Service", ip: "203.0.113.10", host: "Mac.local.", port: 8080)
        let web = bonjourRow(type: "_http._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 80)

        let devices = vm.merge(raw: [test, web])

        #expect(devices.count == 1)
        #expect(Set(devices[0].bonjourServices.map(\.serviceName)) == ["Test Service", "Mac"])
        #expect(Set(devices[0].bonjourServices.map(\.port)) == [80, 8080])
    }

    @Test("the same type and name seen twice is one service")
    func sameTypeAndNameIsOneService() {
        let vm = viewModel()
        let a = bonjourRow(type: "_http._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 80)
        let b = bonjourRow(type: "_http._tcp", name: "Mac", ip: "169.254.46.247", host: "Mac.local.", port: 80)

        let devices = vm.merge(raw: [a, b])

        #expect(devices.count == 1)
        #expect(devices[0].bonjourServices.count == 1)
    }

    // MARK: - Rescan carry

    @Test("a device lists every address its resolves reported, whatever order they arrived in")
    func everyResolvedAddressIsListed() {
        let vm = viewModel()
        let row = bonjourRow(type: "_airplay._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 7000)
        row.resolvedAddresses = ["169.254.46.247", "203.0.113.10"]

        let devices = vm.merge(raw: [row])

        #expect(devices.count == 1)
        #expect(Set(devices[0].addresses) == ["203.0.113.10", "169.254.46.247"])
    }

    @Test("a rescan keeps last scan's rows and unresolved services until they are re-resolved or the scan ends")
    func rescanCarriesRowsAndServices() {
        let vm = viewModel()
        let test = bonjourRow(type: "_http._tcp", name: "Test Service", ip: "203.0.113.10", host: "Mac.local.", port: 8080)
        let air = bonjourRow(type: "_airplay._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 7000)
        vm.apply(raw: [test, air])
        #expect(Set(vm.devices[0].bonjourServices.map(\.serviceName)) == ["Test Service", "Mac"])

        vm.resetForNewScan()
        // Only the airplay row is back so far; the held row and its other service stay.
        let air2 = bonjourRow(type: "_airplay._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 7000)
        vm.apply(raw: [air2])
        #expect(vm.devices.count == 1)
        #expect(Set(vm.devices[0].bonjourServices.map(\.serviceName)) == ["Test Service", "Mac"])

        // An empty first publish keeps the whole previous list.
        vm.apply(raw: [])
        #expect(vm.devices.count == 1)
    }

    @Test("a LAN IPv4 sweep row joins its remembered host when the host's resolves carry only a link-local address")
    func sweepRowJoinsHostWithoutLANAddress() {
        let air = bonjourRow(type: "_airplay._tcp", name: "Mac", ip: "169.254.46.247", host: "Mac.local.", port: 7000)
        let sweep = sweepRow("203.0.113.10")
        let plan = NetworkScanViewModel.plan(raw: [air, sweep], own: .none, remembered: ["203.0.113.10": "mac.local"])
        #expect(plan.effectiveIPByRow == ["203.0.113.10", "203.0.113.10"])
    }

    @Test("without a host name the display name is the same whichever row arrived first, and never an SSDP header")
    func fallbackNameDoesNotDependOnOrder() {
        let vm = viewModel()
        let bonjour = bonjourRow(type: "_airplay._tcp", name: "Living Room", ip: "203.0.113.40", host: nil, port: 7000)
        let ssdp = NetworkScanner.Device(serviceName: "uuid:x", serviceDomain: "ssdp", serviceType: "ssdp")
        ssdp.resolvedIPAddress = "203.0.113.40"
        ssdp.ssdpServer = "Linux/5 UPnP/1.1 X/1"
        let forward = vm.merge(raw: [ssdp, bonjour, sweepRow("203.0.113.40")])
        let reversed = vm.merge(raw: [sweepRow("203.0.113.40"), bonjour, ssdp])
        #expect(forward.map(\.hostname) == ["Living Room"])
        #expect(reversed.map(\.hostname) == ["Living Room"])
    }

    @Test("a Mac is a computer whatever order its services arrive in, and each device type has its own label")
    func macTypeAndLabels() {
        let air = BonjourService(serviceType: "_airplay._tcp", serviceName: "Mac", port: 7000)
        let smb = BonjourService(serviceType: "_smb._tcp", serviceName: "Mac", port: 445)
        let first = DiscoveredDevice(hostname: "Mac", ipAddress: "203.0.113.50", manufacturer: "Apple", bonjourServices: [air, smb])
        let second = DiscoveredDevice(hostname: "Mac", ipAddress: "203.0.113.50", manufacturer: "Apple", bonjourServices: [smb, air])
        #expect(first.deviceType == .computer && second.deviceType == .computer)
        #expect(Set(DeviceType.allCases.map(\.label)).count == DeviceType.allCases.count)
    }

    @Test("the UPnP friendly name is read as plain text from the root device and capped at 64 characters")
    func friendlyNameParsing() {
        let xml = "<root><device><friendlyName>  Living\tRoom   TV </friendlyName><deviceList><device><friendlyName>Embedded</friendlyName></device></deviceList></device></root>"
        #expect(SSDPDeviceDescription.parse(Data(xml.utf8))?.friendlyName == "Living Room TV")
        let long = "<root><device><friendlyName>\(String(repeating: "x", count: 200))</friendlyName></device></root>"
        #expect(SSDPDeviceDescription.parse(Data(long.utf8))?.friendlyName?.count == 64)
    }

    @Test("a device on another network is flagged, one on the phone's subnet is not")
    func otherNetworkIsFlagged() {
        let subnet = LocalInterfaces.IPv4Subnet(network: LocalInterfaces.ipv4Value("10.10.30.0")!, prefixLength: 24)
        let vm = NetworkScanViewModel(ownAddresses: { LocalInterfaces.OwnAddresses(primary: ["10.10.30.5"], all: ["10.10.30.5"], ipv4Subnets: [subnet]) },
                                      probe: { _, _ in })
        let camera = bonjourRow(type: "_http._tcp", name: "Camera", ip: "10.10.10.87", host: "Camera.local.", port: 80)
        let tv = bonjourRow(type: "_http._tcp", name: "TV", ip: "10.10.30.80", host: "TV.local.", port: 80)

        let byName = Dictionary(uniqueKeysWithValues: vm.merge(raw: [camera, tv]).map { ($0.hostname, $0.isOnLocalSubnet) })

        #expect(byName["Camera.local."] == false)
        #expect(byName["TV.local."] == true)
    }

    // MARK: - Services without a device

    @Test("a Bonjour row whose resolve has not answered yet is neither a device nor a service")
    func pendingRowIsNeitherDeviceNorService() {
        let vm = viewModel()
        #expect(NetworkScanner.Device(serviceName: "x", serviceDomain: "local.", serviceType: "_http._tcp.").resolveSettled == false)
        let pending = bonjourRow(type: "_http._tcp.", name: "Test Service", ip: nil, host: nil, port: 8080)
        pending.resolveSettled = false
        let lan = bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)

        let result = vm.mergeScan(raw: [pending, lan])

        #expect(result.devices.map(\.ipAddress) == ["203.0.113.10"])
        #expect(result.services.isEmpty)
    }

    @Test("a row whose resolve failed is shown as a service")
    func failedResolveRowIsAService() {
        let vm = viewModel()
        let failed = bonjourRow(type: "_http._tcp.", name: "Test Service", ip: nil, host: nil, port: 8080)
        failed.port = nil
        let lan = bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)

        let result = vm.mergeScan(raw: [failed, lan])

        #expect(result.devices.map(\.ipAddress) == ["203.0.113.10"])
        #expect(result.services.map(\.name) == ["Test Service"])
    }

    @Test("a service that never resolved is a service entry, not a device row")
    func unresolvedServiceIsAServiceNotADevice() {
        let vm = viewModel()
        let pending = bonjourRow(type: "_http._tcp.", name: "burst37", ip: nil, host: nil, port: 8037)
        pending.port = nil
        let resolved = bonjourRow(type: "_http._tcp", name: "nas", ip: "203.0.113.20", host: "nas.local.")

        let result = vm.mergeScan(raw: [pending, resolved])

        #expect(result.devices.map(\.ipAddress) == ["203.0.113.20"])
        #expect(result.services.map(\.name) == ["burst37"])
        #expect(result.services[0].serviceType == "_http._tcp.")
        #expect(result.services[0].port == nil && result.services[0].hostName == nil)
    }

    @Test("a fallback-resolved row with no device for its host stays a service and keeps its host name")
    func fallbackOnlyRowIsAService() {
        let vm = viewModel()
        let fallback = bonjourRow(type: "_http._tcp", name: "burst12", ip: nil, host: "Mac.local.", port: 8012)
        let other = bonjourRow(type: "_ssh._tcp", name: "nas", ip: "203.0.113.20", host: "nas.local.", port: 22)

        let result = vm.mergeScan(raw: [fallback, other])

        #expect(result.devices.map(\.ipAddress) == ["203.0.113.20"])
        #expect(result.services.count == 1)
        #expect(result.services[0].hostName == "Mac.local." && result.services[0].port == 8012)
    }

    @Test("a service attaches to the device whose host key matches, whatever the case or trailing dot")
    func serviceAttachesToMatchingDevice() {
        let vm = viewModel()
        let fallback = bonjourRow(type: "_http._tcp", name: "burst12", ip: nil, host: "MAC.local", port: 8012)
        let lan = bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)

        let result = vm.mergeScan(raw: [fallback, lan])

        #expect(result.devices.map(\.ipAddress) == ["203.0.113.10"])
        #expect(result.devices[0].bonjourServices.count == 2)
        #expect(result.services.isEmpty)
    }

    @Test("an SSDP row whose LOCATION is a DNS name becomes a service, and counts stay device-only")
    func ssdpDNSNameIsAService() {
        let vm = viewModel()
        let ssdp = NetworkScanner.Device(serviceName: "uuid:tv", serviceDomain: "ssdp", serviceType: "ssdp")
        ssdp.friendlyName = "Smart TV"
        ssdp.hostName = "tv.example.com"
        ssdp.port = 8080
        ssdp.resolveSettled = true
        let lan = bonjourRow(type: "_ssh._tcp", name: "Mac", ip: "203.0.113.10", host: "Mac.local.", port: 22)

        let result = vm.mergeScan(raw: [ssdp, lan])

        // The header counts devices.count, secure and vulnerable from devices only, so a service never inflates them.
        #expect(result.devices.count == 1)
        #expect(result.services.count == 1)
        #expect(result.services[0].isSSDP && result.services[0].name == "Smart TV" && result.services[0].port == 8080)
    }

    @Test("service entries come out in the same order whatever order the rows arrive in")
    func serviceOrderIsDeterministic() {
        let vm = viewModel()
        let a = bonjourRow(type: "_http._tcp", name: "b", ip: nil, host: nil)
        let b = bonjourRow(type: "_ssh._tcp", name: "a", ip: nil, host: nil)

        #expect(vm.mergeScan(raw: [a, b]).services.map(\.id) == vm.mergeScan(raw: [b, a]).services.map(\.id))
    }

    // MARK: - Address preference

    @Test("the scanner prefers a LAN IPv4 over link-local IPv4 over routable IPv6 over fe80 over a bare host name")
    func preferredAddressOrder() {
        #expect(NetworkScanner.preferredAddress(from: ["169.254.46.247", "192.168.1.10"]) == "192.168.1.10")
        #expect(NetworkScanner.preferredAddress(from: ["fe80::1", "169.254.46.247"]) == "169.254.46.247")
        #expect(NetworkScanner.preferredAddress(from: ["fe80::1", "2001:db8::1"]) == "2001:db8::1")
        #expect(NetworkScanner.preferredAddress(from: ["192.168.1.10", "192.168.1.11"]) == "192.168.1.10")
        #expect(NetworkScanner.preferredAddress(from: ["Mac.local.", "fe80::1"]) == "fe80::1")
        #expect(NetworkScanner.preferredAddress(from: ["Mac.local."]) == "Mac.local.")
        #expect(NetworkScanner.preferredAddress(from: []) == nil)
    }

    @Test("ties within a rank resolve the same way regardless of input order")
    func preferredAddressTiesAreOrderIndependent() {
        #expect(NetworkScanner.preferredAddress(from: ["192.168.1.10", "192.168.1.9"]) == "192.168.1.9")
        #expect(NetworkScanner.preferredAddress(from: ["192.168.1.9", "192.168.1.10"]) == "192.168.1.9")
        #expect(NetworkScanner.preferredAddress(from: ["2001:db8::9", "2001:db8::1"]) == "2001:db8::1")
        #expect(NetworkScanner.preferredAddress(from: ["2001:db8::1", "2001:db8::9"]) == "2001:db8::1")
    }
}
