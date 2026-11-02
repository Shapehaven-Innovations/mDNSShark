// mDNSSharkTests/PortScannerCameraTests.swift
import Testing
import Foundation
import Network
import DeviceFingerprint
@testable import mDNSShark

/// Accepts connections on an ephemeral loopback port, optionally speaks first or replies to the first bytes, and records every byte and the close.
private final class LoopbackListener: @unchecked Sendable {
    private let listener: NWListener
    private let greeting: Data?
    private let reply: Data?
    private let lock = NSLock()
    private var captured = Data()
    private var closed = false
    private var replied = false
    private var connections: [NWConnection] = []

    init?(greeting: Data? = nil, reply: Data? = nil) {
        guard let l = try? NWListener(using: .tcp, on: .any) else { return nil }
        listener = l
        self.greeting = greeting
        self.reply = reply
        l.newConnectionHandler = { [weak self] connection in
            guard let self else { return }
            self.lock.lock(); self.connections.append(connection); self.lock.unlock()
            connection.start(queue: .global())
            if let greeting = self.greeting { connection.send(content: greeting, completion: .contentProcessed { _ in }) }
            self.drain(connection)
        }
    }

    /// Starts listening and returns the port the system chose, or nil if the listener failed.
    func start() async -> Int? {
        await withCheckedContinuation { (c: CheckedContinuation<Int?, Never>) in
            let once = NSLock()
            var done = false
            listener.stateUpdateHandler = { [listener] state in
                var result: Int??
                switch state {
                case .ready: result = .some(listener.port.map { Int($0.rawValue) })
                case .failed, .cancelled: result = .some(nil)
                default: break
                }
                guard let value = result else { return }
                once.lock(); defer { once.unlock() }
                if !done { done = true; c.resume(returning: value) }
            }
            listener.start(queue: .global())
        }
    }

    private func drain(_ connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            self.lock.lock()
            if let data { self.captured.append(data) }
            if isComplete || error != nil { self.closed = true }
            let sendReply = !(data ?? Data()).isEmpty && !self.replied && self.reply != nil
            if sendReply { self.replied = true }
            self.lock.unlock()
            if sendReply, let reply = self.reply { connection.send(content: reply, completion: .contentProcessed { _ in }) }
            if error == nil, !isComplete { self.drain(connection) }
        }
    }

    var bytes: Data { lock.lock(); defer { lock.unlock() }; return captured }
    var sawClose: Bool { lock.lock(); defer { lock.unlock() }; return closed }
    func stop() { listener.cancel(); lock.lock(); connections.forEach { $0.cancel() }; lock.unlock() }
}

@Suite("PortScanner camera ports")
struct PortScannerCameraTests {

    private func scan(_ scanner: PortScanner, _ ports: [Int], timeout: TimeInterval = 1.5) async -> [ScannedPort] {
        await withCheckedContinuation { c in
            scanner.scan(ip: "127.0.0.1", ports: ports, timeout: timeout) { c.resume(returning: $0) }
        }
    }

    @Test("554 and 8000 are always scanned, the connect-only ports only with a camera hint")
    func portListsFollowTheHint() {
        let off = PortScanner.ports(cameraHint: false)
        let on = PortScanner.ports(cameraHint: true)
        #expect(off == PortScanner.uniFiRelevantPorts + [554, 8000])
        for port in [8554, 37777, 34567, 2020, 9000, 1935, 7441] {
            #expect(!off.contains(port))
            #expect(on.contains(port))
        }
        #expect(Set(on).isSuperset(of: off))
    }

    @Test("a connect-only port is reported open, closed right after connect, and receives zero bytes")
    func connectOnlyWritesNothing() async throws {
        let listener = try #require(LoopbackListener())
        let port = try #require(await listener.start())
        defer { listener.stop() }
        let timeout: TimeInterval = 10
        let started = Date()
        let result = await scan(PortScanner(connectOnlyPorts: [port]), [port], timeout: timeout)
        let elapsed = Date().timeIntervalSince(started)
        try await Task.sleep(nanoseconds: 300_000_000)
        #expect(elapsed < timeout / 2, "the scanner waited for a banner instead of closing")
        #expect(result.map(\.port) == [port])
        #expect(result.first?.banner == nil)
        #expect(listener.bytes.isEmpty)
        #expect(listener.sawClose)
    }

    @Test("port 8000 is read only: the Hikvision banner is labelled and nothing is written")
    func port8000ReadOnly() async throws {
        let banner = Data([0, 0, 0, 0x10, 0, 0, 0, 0x1e, 0, 0, 0, 0x1e, 0, 0, 0, 0])
        let listener = try #require(LoopbackListener(greeting: banner))
        let port = try #require(await listener.start())
        defer { listener.stop() }
        let result = await scan(PortScanner(hikvisionControlPort: port), [port])
        try await Task.sleep(nanoseconds: 300_000_000)
        #expect(result.first?.banner == "Hikvision camera control port (binary banner)")
        #expect(listener.bytes.isEmpty)
    }

    @Test("the RTSP port gets exactly one OPTIONS request and its reply becomes the literal banner text")
    func rtspSendsOneOptions() async throws {
        let raw = "RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nServer: Dahua Rtsp Server\r\nWWW-Authenticate: Digest realm=\"Login to 4K0123\", nonce=\"abc\"\r\n\r\n"
        let listener = try #require(LoopbackListener(reply: Data(raw.utf8)))
        let port = try #require(await listener.start())
        defer { listener.stop() }
        let result = await scan(PortScanner(rtspPort: port), [port])
        try await Task.sleep(nanoseconds: 300_000_000)
        #expect(listener.bytes == RTSPReply.optionsRequest(ip: "127.0.0.1", port: port))
        let expected = try #require(RTSPReply.parse(Data(raw.utf8))).bannerText
        #expect(result.map(\.port) == [port])
        #expect(result.first?.banner == expected)
        #expect(expected.hasPrefix("RTSP/1.0 401 Unauthorized | Server: Dahua Rtsp Server"))
    }

    @Test("port 8000 labelling: non-matching, truncated and the 0d variant stay literal or empty")
    func port8000Matching() {
        #expect(PortScanner().listenBanner(port: 8000, data: Data("SSH-2.0-x".utf8)) == "SSH-2.0-x")
        #expect(PortScanner().listenBanner(port: 8000, data: Data([0, 0, 0, 0x10, 0, 0, 0, 0x1e])) != CameraPortBanner.hikvisionControlLabel)
        #expect(PortScanner().listenBanner(port: 8000, data: Data()) == nil)
        #expect(PortScanner().listenBanner(port: 22, data: Data([0, 0, 0, 0x10, 0, 0, 0, 0x1e, 0, 0, 0, 0x1e, 0, 0, 0, 0])) != CameraPortBanner.hikvisionControlLabel)
        #expect(PortScanner().listenBanner(port: 8000, data: Data([0, 0, 0, 0x10, 0, 0, 0, 0x0d, 0, 0, 0, 0x0d, 0, 0, 0, 0])) != CameraPortBanner.hikvisionControlLabel)
    }

    @Test("an RTSP reply becomes literal banner text that feeds the manufacturer guess")
    func rtspBannerText() {
        let reply = Data("RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nServer: Dahua Rtsp Server\r\n\r\n".utf8)
        let banner = PortScanner.rtspBanner(from: reply)
        #expect(banner == "RTSP/1.0 401 Unauthorized | Server: Dahua Rtsp Server")
        #expect(guessFromBanner(banner ?? "").manufacturer == "Dahua")
        #expect(PortScanner.rtspBanner(from: nil) == nil)
    }
}

@MainActor
@Suite("Camera hint for the connect-only ports")
struct CameraHintViewModelTests {
    private func viewModel() -> NetworkScanViewModel {
        NetworkScanViewModel(ownAddresses: { [] }, probe: { _, _ in })
    }

    private func row(type: String, name: String, ip: String) -> NetworkScanner.Device {
        let row = NetworkScanner.Device(serviceName: name, serviceDomain: "local.", serviceType: type)
        row.resolvedIPAddress = ip
        row.hostName = "\(name).local."
        row.port = 80
        row.resolveSettled = true
        return row
    }

    @Test("an _rtsp._tcp row sets the hint for its address, and a new scan clears it")
    func rtspRowSetsHint() {
        let vm = viewModel()
        _ = vm.merge(raw: [row(type: "_rtsp._tcp", name: "cam", ip: "203.0.113.20")])
        #expect(vm.cameraHint(forProbeIP: "203.0.113.20", arpMAC: nil))
        #expect(!vm.cameraHint(forProbeIP: "203.0.113.21", arpMAC: nil))
        vm.resetForNewScan()
        #expect(!vm.cameraHint(forProbeIP: "203.0.113.20", arpMAC: nil))
    }

    @Test("a Hikvision OUI MAC is a hint and an Apple MAC is not")
    func macVendorHint() {
        let vm = viewModel()
        #expect(vm.cameraHint(forProbeIP: "203.0.113.30", arpMAC: "00:bc:99:11:22:33"))
        #expect(!vm.cameraHint(forProbeIP: "203.0.113.30", arpMAC: "00:03:93:11:22:33"))
        #expect(!vm.cameraHint(forProbeIP: "203.0.113.30", arpMAC: nil))
    }

    @Test("a merged row whose device type is camera is a hint")
    func mergedCameraRowHint() {
        let vm = viewModel()
        vm.devices = [DiscoveredDevice(hostname: "cam", ipAddress: "203.0.113.40",
                                       bonjourServices: [BonjourService(serviceType: "_axis-video._tcp", serviceName: "AXIS", port: 554)])]
        #expect(vm.devices[0].deviceType == .camera)
        #expect(vm.cameraHint(forProbeIP: "203.0.113.40", arpMAC: nil))
    }

    @Test("an AirPlay TV and a plain host are not hints")
    func nonCameraHosts() {
        let vm = viewModel()
        vm.devices = vm.merge(raw: [row(type: "_airplay._tcp", name: "tv", ip: "203.0.113.50"),
                                    row(type: "_http._tcp", name: "plain", ip: "203.0.113.51")])
        #expect(!vm.cameraHint(forProbeIP: "203.0.113.50", arpMAC: nil))
        #expect(!vm.cameraHint(forProbeIP: "203.0.113.51", arpMAC: nil))
    }
}
