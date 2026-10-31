// mDNSSharkTests/MDNSEmptyStateTests.swift
import Testing
@testable import mDNSShark

@Suite("mDNS chip empty state follows capture state, filter and listener status")
struct MDNSEmptyStateTests {

    @Test func notCapturingExplainsTheListener() {
        let text = MDNSEmptyState.text(isCapturing: false, filterOn: true, listenerStatus: "")
        #expect(text.contains("Tap Start"))
        #expect(text.contains("224.0.0.251:5353"))
    }

    @Test func filterOffPointsAtSettings() {
        let text = MDNSEmptyState.text(isCapturing: true, filterOn: false, listenerStatus: "listening on en0 (ifindex 13)")
        #expect(text.contains("Capture Filters"))
    }

    @Test func listeningNamesTheInterface() {
        let text = MDNSEmptyState.text(isCapturing: true, filterOn: true, listenerStatus: "listening on en0 (ifindex 13)")
        #expect(text.hasPrefix("Listening for mDNS on en0"))
        #expect(text.contains("another device"))
    }

    @Test func failureShowsTheRawStatus() {
        let status = "failed: bind errno 48 (Address already in use)"
        let text = MDNSEmptyState.text(isCapturing: true, filterOn: true, listenerStatus: status)
        #expect(text.contains("could not start"))
        #expect(text.contains(status))
    }

    @Test func capturingWithNoStatusYetIsNeutral() {
        let text = MDNSEmptyState.text(isCapturing: true, filterOn: true, listenerStatus: "")
        #expect(text.contains("Waiting for the mDNS listener"))
    }

    @Test func interfaceNameParsesFromStatus() {
        #expect(MDNSEmptyState.interfaceName(from: "listening on en0 (ifindex 13)") == "en0")
        #expect(MDNSEmptyState.interfaceName(from: "listening on en1") == "en1")
        #expect(MDNSEmptyState.interfaceName(from: "failed: bind errno 48") == nil)
    }
}
