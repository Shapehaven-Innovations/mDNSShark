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

    @Test func multiInterfaceStatusListsEveryListeningInterface() {
        let status = "listening on en0 (ifindex 13), bridge100 (ifindex 20), IPv6 only; en3 failed: bind errno 48 (Address already in use)"
        #expect(MDNSEmptyState.interfaceNames(from: status) == ["en0", "bridge100"])
        #expect(MDNSEmptyState.interfaceName(from: status) == "en0")
        let text = MDNSEmptyState.text(isCapturing: true, filterOn: true, listenerStatus: status)
        #expect(text.hasPrefix("Listening for mDNS on en0 and bridge100."))
        let three = MDNSEmptyState.text(isCapturing: true, filterOn: true, listenerStatus: "listening on en0 (ifindex 13), en3 (ifindex 21), bridge100 (ifindex 20)")
        #expect(three.hasPrefix("Listening for mDNS on en0, en3 and bridge100."))
    }

    @Test func removedInterfaceClauseIsNotAListeningInterface() {
        // After a reconcile the extension rewrites the line; an interface that went away trails after the semicolon.
        let status = "listening on en0 (ifindex 13); bridge100 removed (interface went away)"
        #expect(MDNSEmptyState.interfaceNames(from: status) == ["en0"])
        #expect(MDNSEmptyState.text(isCapturing: true, filterOn: true, listenerStatus: status).hasPrefix("Listening for mDNS on en0."))
        let allGone = "removed (interface went away)"
        #expect(MDNSEmptyState.interfaceNames(from: allGone).isEmpty)
        #expect(MDNSEmptyState.text(isCapturing: true, filterOn: true, listenerStatus: allGone).contains("could not start"))
    }
}
