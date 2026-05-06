// PirSnapshotResolverTests.swift
// Verifies the PIR endpoint snapshot-match selection used by `buildAndProveDelegation`.
// See PirSnapshotResolver.swift for context (ZCA-229).

import Foundation
import XCTest
@testable import ZcashLightClientKit

final class PirSnapshotResolverTests: XCTestCase {
    func testEmptyEndpointsThrowsNoEndpointsConfigured() async {
        let resolver = PirSnapshotResolver(probe: StubProbe())
        do {
            _ = try await resolver.resolve(endpoints: [], expectedSnapshotHeight: 100)
            XCTFail("expected noEndpointsConfigured")
        } catch let error as PirSnapshotResolverError {
            XCTAssertEqual(error, .noEndpointsConfigured)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testFirstMatchingEndpointInConfigOrderIsChosen() async throws {
        // Mix of mismatched (behind), matching, and matching: matching endpoints all
        // share the same height (= expected) by definition, so the resolver picks
        // the first one in config order regardless of how many are matching.
        let probe = StubProbe(outcomes: [
            "https://a": .mismatched(height: 90),
            "https://b": .matching(height: 100),
            "https://c": .matching(height: 100)
        ])
        let resolver = PirSnapshotResolver(probe: probe)

        let chosen = try await resolver.resolve(
            endpoints: ["https://a", "https://b", "https://c"],
            expectedSnapshotHeight: 100
        )
        XCTAssertEqual(chosen, "https://b")
    }

    func testMatchingEndpointAfterMismatchIsChosen() async throws {
        // Matching endpoint is not first in config order — must still be selected
        // over the leading mismatched one.
        let probe = StubProbe(outcomes: [
            "https://primary": .mismatched(height: 99),
            "https://backup": .matching(height: 100)
        ])
        let resolver = PirSnapshotResolver(probe: probe)

        let chosen = try await resolver.resolve(
            endpoints: ["https://primary", "https://backup"],
            expectedSnapshotHeight: 100
        )
        XCTAssertEqual(chosen, "https://backup")
    }

    func testExactMatchIsAccepted() async throws {
        let probe = StubProbe(outcomes: [
            "https://exact": .matching(height: 100)
        ])
        let resolver = PirSnapshotResolver(probe: probe)

        let chosen = try await resolver.resolve(
            endpoints: ["https://exact"],
            expectedSnapshotHeight: 100
        )
        XCTAssertEqual(chosen, "https://exact")
    }

    /// Strict-equality regression: a server ahead of the round's snapshot is just
    /// as wrong as one behind it — proofs are bound to the round's specific snapshot.
    func testHeightAboveExpectedIsRejected() async {
        let probe = StubProbe(outcomes: [
            "https://ahead": .mismatched(height: 200)
        ])
        let resolver = PirSnapshotResolver(probe: probe)

        do {
            _ = try await resolver.resolve(endpoints: ["https://ahead"], expectedSnapshotHeight: 100)
            XCTFail("expected noMatchingEndpoint")
        } catch let error as PirSnapshotResolverError {
            switch error {
            case .noMatchingEndpoint(let expected, let details):
                XCTAssertEqual(expected, 100)
                XCTAssertEqual(details.first?.status, .mismatched(height: 200))
            default:
                XCTFail("unexpected resolver error: \(error)")
            }
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testAllMismatchedThrowsNoMatchingWithDiagnostics() async {
        // Cover both directions: one behind, one ahead. Both must be rejected.
        let probe = StubProbe(outcomes: [
            "https://behind": .mismatched(height: 99),
            "https://ahead": .mismatched(height: 101)
        ])
        let resolver = PirSnapshotResolver(probe: probe)

        do {
            _ = try await resolver.resolve(
                endpoints: ["https://behind", "https://ahead"],
                expectedSnapshotHeight: 100
            )
            XCTFail("expected noMatchingEndpoint")
        } catch let error as PirSnapshotResolverError {
            switch error {
            case .noMatchingEndpoint(let expected, let details):
                XCTAssertEqual(expected, 100)
                XCTAssertEqual(details.count, 2)
                XCTAssertEqual(details[0].url, "https://behind")
                XCTAssertEqual(details[0].status, .mismatched(height: 99))
                XCTAssertEqual(details[1].url, "https://ahead")
                XCTAssertEqual(details[1].status, .mismatched(height: 101))
            default:
                XCTFail("unexpected resolver error: \(error)")
            }
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testMissingHeightIsTreatedAsNotMatching() async {
        let probe = StubProbe(outcomes: [
            "https://no-height": .missingHeight,
            "https://mismatched": .mismatched(height: 10)
        ])
        let resolver = PirSnapshotResolver(probe: probe)

        do {
            _ = try await resolver.resolve(
                endpoints: ["https://no-height", "https://mismatched"],
                expectedSnapshotHeight: 100
            )
            XCTFail("expected noMatchingEndpoint")
        } catch let error as PirSnapshotResolverError {
            guard case .noMatchingEndpoint(_, let details) = error else {
                XCTFail("unexpected error: \(error)")
                return
            }
            XCTAssertEqual(details[0].status, .missingHeight)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testUnreachableIsTreatedAsNotMatching() async {
        let probe = StubProbe(outcomes: [
            "https://down": .unreachable(reason: "timeout"),
            "https://mismatched": .mismatched(height: 90)
        ])
        let resolver = PirSnapshotResolver(probe: probe)

        do {
            _ = try await resolver.resolve(
                endpoints: ["https://down", "https://mismatched"],
                expectedSnapshotHeight: 100
            )
            XCTFail("expected noMatchingEndpoint")
        } catch let error as PirSnapshotResolverError {
            guard case .noMatchingEndpoint = error else {
                XCTFail("unexpected error: \(error)")
                return
            }
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testProbeReceivesCorrectExpectedHeightAndUrls() async throws {
        let probe = StubProbe(outcomes: [
            "https://match": .matching(height: 173)
        ])
        let resolver = PirSnapshotResolver(probe: probe)

        _ = try await resolver.resolve(endpoints: ["https://match"], expectedSnapshotHeight: 173)

        let calls = await probe.callsMade
        XCTAssertEqual(calls.count, 1)
        XCTAssertEqual(calls[0].url, "https://match")
        XCTAssertEqual(calls[0].expected, 173)
    }

    /// Diagnostics surface includes one row per endpoint so operators can tell
    /// "everything is mismatched" from "the network is down".
    func testNoMatchingErrorListsAllEndpointsRegardlessOfStatus() async {
        let probe = StubProbe(outcomes: [
            "https://x": .unreachable(reason: "EOF"),
            "https://y": .missingHeight,
            "https://z": .mismatched(height: 5)
        ])
        let resolver = PirSnapshotResolver(probe: probe)

        do {
            _ = try await resolver.resolve(
                endpoints: ["https://x", "https://y", "https://z"],
                expectedSnapshotHeight: 100
            )
            XCTFail("expected noMatchingEndpoint")
        } catch let error as PirSnapshotResolverError {
            guard case .noMatchingEndpoint(_, let details) = error else {
                XCTFail("unexpected error: \(error)")
                return
            }
            XCTAssertEqual(details.map(\.url), ["https://x", "https://y", "https://z"])
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    /// Sanity: the user-facing error message names the expected snapshot height
    /// and includes per-endpoint diagnostics, since this surfaces in voting UX.
    func testErrorDescriptionMentionsSnapshotAndDetails() {
        let error = PirSnapshotResolverError.noMatchingEndpoint(
            expected: 1234,
            details: [
                PirSnapshotProbeOutcome(url: "https://a", status: .mismatched(height: 100)),
                PirSnapshotProbeOutcome(url: "https://b", status: .missingHeight)
            ]
        )
        let description = error.errorDescription ?? ""
        XCTAssertTrue(description.contains("1234"), "missing expected height: \(description)")
        XCTAssertTrue(description.contains("https://a"), "missing endpoint a: \(description)")
        XCTAssertTrue(description.contains("https://b"), "missing endpoint b: \(description)")
    }
}

// MARK: - HTTP probe end-to-end tests

/// Exercises `HTTPPirSnapshotProbe.probe(...)` end-to-end via a `URLProtocol`
/// stub so the actual `==`/`!=` classification, `/root` URL construction, HTTP
/// status handling, and JSON decoding paths run for real. The resolver-level
/// tests above only feed pre-classified outcomes through a `StubProbe`; these
/// tests cover the probe itself.
final class HTTPPirSnapshotProbeTests: XCTestCase {
    override func setUp() {
        super.setUp()
        StubURLProtocol.reset()
    }

    override func tearDown() {
        StubURLProtocol.reset()
        super.tearDown()
    }

    private func makeProbe() -> HTTPPirSnapshotProbe {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        return HTTPPirSnapshotProbe(session: URLSession(configuration: config))
    }

    private func rootInfoJSON(height: UInt64?) -> Data {
        let heightField = height.map { "\"height\": \($0)" } ?? "\"height\": null"
        return """
        {
          "root29": "deadbeef",
          "root25": "cafebabe",
          "num_ranges": 42,
          "pir_depth": 25,
          \(heightField)
        }
        """.data(using: .utf8)!
    }

    /// Strict-equality regression — `height == expected` must classify as `.matching`.
    func testProbeReturnsMatchingWhenHeightEqualsExpected() async {
        StubURLProtocol.handler = { _ in (200, self.rootInfoJSON(height: 100)) }

        let outcome = await makeProbe().probe(url: "https://pir.test", expectedSnapshotHeight: 100)

        XCTAssertEqual(outcome.url, "https://pir.test")
        XCTAssertEqual(outcome.status, .matching(height: 100))
    }

    /// Strict-equality regression — `height < expected` must classify as `.mismatched`,
    /// not `.matching`. This is the "behind / catching up" case.
    func testProbeReturnsMismatchedWhenHeightBelowExpected() async {
        StubURLProtocol.handler = { _ in (200, self.rootInfoJSON(height: 99)) }

        let outcome = await makeProbe().probe(url: "https://pir.test", expectedSnapshotHeight: 100)

        XCTAssertEqual(outcome.status, .mismatched(height: 99))
    }

    /// Strict-equality regression — `height > expected` must ALSO classify as
    /// `.mismatched`. Under the previous `>=` policy this case would have been
    /// `.fresh`/`.matching`, which is exactly the bug the `==` change closes.
    func testProbeReturnsMismatchedWhenHeightAboveExpected() async {
        StubURLProtocol.handler = { _ in (200, self.rootInfoJSON(height: 101)) }

        let outcome = await makeProbe().probe(url: "https://pir.test", expectedSnapshotHeight: 100)

        XCTAssertEqual(outcome.status, .mismatched(height: 101))
    }

    /// `RootInfo.height: Option<u64>` is allowed to be null on the wire.
    /// The probe must surface that as `.missingHeight` (not `.unreachable`).
    func testProbeReturnsMissingHeightWhenJsonHeightIsNull() async {
        StubURLProtocol.handler = { _ in (200, self.rootInfoJSON(height: nil)) }

        let outcome = await makeProbe().probe(url: "https://pir.test", expectedSnapshotHeight: 100)

        XCTAssertEqual(outcome.status, .missingHeight)
    }

    /// Non-200 responses must not be confused with successful probes that
    /// returned a usable height — they're plainly unreachable.
    func testProbeReturnsUnreachableOnNon200Response() async {
        StubURLProtocol.handler = { _ in (503, Data()) }

        let outcome = await makeProbe().probe(url: "https://pir.test", expectedSnapshotHeight: 100)

        switch outcome.status {
        case .unreachable(let reason):
            XCTAssertTrue(reason.contains("503"), "reason should mention 503: \(reason)")
        default:
            XCTFail("expected unreachable, got \(outcome.status)")
        }
    }

    /// 200 with garbage body must be `.unreachable` with a decode reason — not
    /// crash, not be misclassified as `.missingHeight`.
    func testProbeReturnsUnreachableOnMalformedJson() async {
        StubURLProtocol.handler = { _ in (200, Data("not json".utf8)) }

        let outcome = await makeProbe().probe(url: "https://pir.test", expectedSnapshotHeight: 100)

        switch outcome.status {
        case .unreachable(let reason):
            XCTAssertTrue(reason.contains("decode"), "reason should mention decode: \(reason)")
        default:
            XCTFail("expected unreachable, got \(outcome.status)")
        }
    }

    /// Network-layer error from URLSession (DNS, connection refused, etc.)
    /// must be `.unreachable`, not propagate as a thrown error.
    func testProbeReturnsUnreachableOnTransportError() async {
        StubURLProtocol.handler = { _ in throw URLError(.cannotConnectToHost) }

        let outcome = await makeProbe().probe(url: "https://pir.test", expectedSnapshotHeight: 100)

        if case .unreachable = outcome.status {
            // expected
        } else {
            XCTFail("expected unreachable, got \(outcome.status)")
        }
    }

    /// The probe appends `/root` to the configured base URL and tolerates a
    /// trailing slash on the base. Confirms the URL the probe actually hits.
    func testProbeAppendsRootPathAndTrimsTrailingSlash() async {
        await assertProbeHits(baseUrl: "https://pir.test", expectedPath: "/root")
        await assertProbeHits(baseUrl: "https://pir.test/", expectedPath: "/root")
    }

    private func assertProbeHits(baseUrl: String, expectedPath: String) async {
        nonisolated(unsafe) var capturedURL: URL?
        StubURLProtocol.handler = { request in
            capturedURL = request.url
            return (200, self.rootInfoJSON(height: 100))
        }

        _ = await makeProbe().probe(url: baseUrl, expectedSnapshotHeight: 100)

        XCTAssertEqual(capturedURL?.path, expectedPath, "for base \(baseUrl)")
    }

    /// Empty / unparseable URL strings must be reported as unreachable rather
    /// than throwing or crashing — caller may have a malformed config row.
    func testProbeReturnsUnreachableOnInvalidURL() async {
        let outcome = await makeProbe().probe(url: "", expectedSnapshotHeight: 100)

        if case .unreachable = outcome.status {
            // expected
        } else {
            XCTFail("expected unreachable for empty URL, got \(outcome.status)")
        }
    }
}

// MARK: - HTTP probe wire-shape test

final class HTTPPirSnapshotProbeWireShapeTests: XCTestCase {
    /// Locks in the wire compatibility with `vote-nullifier-pir`'s `RootInfo`
    /// JSON: serde defaults serialize `num_ranges`/`pir_depth`/`height` as
    /// snake_case, and `height` is `Option<u64>`. Decoding via the
    /// resolver's internal type would couple us to that private type, so we
    /// re-decode through `JSONSerialization` to assert the shape is correct.
    func testRootInfoJsonShapeMatchesPirServer() throws {
        let json = """
        {
          "root29": "deadbeef",
          "root25": "cafebabe",
          "num_ranges": 42,
          "pir_depth": 25,
          "height": 173
        }
        """.data(using: .utf8)!

        let object = try JSONSerialization.jsonObject(with: json) as? [String: Any]
        XCTAssertEqual(object?["height"] as? UInt64, 173)
        XCTAssertEqual(object?["num_ranges"] as? Int, 42)
        XCTAssertEqual(object?["pir_depth"] as? Int, 25)
    }
}

// MARK: - Test doubles

/// Records every probe call so tests can assert what the resolver asked for.
private actor ProbeCallLog {
    private(set) var calls: [(url: String, expected: UInt64)] = []
    func record(_ url: String, _ expected: UInt64) {
        calls.append((url, expected))
    }
}

private struct StubProbe: PirSnapshotProbing {
    let outcomes: [String: PirSnapshotProbeOutcome.Status]
    private let log = ProbeCallLog()

    init(outcomes: [String: PirSnapshotProbeOutcome.Status] = [:]) {
        self.outcomes = outcomes
    }

    func probe(url: String, expectedSnapshotHeight: UInt64) async -> PirSnapshotProbeOutcome {
        await log.record(url, expectedSnapshotHeight)
        let status = outcomes[url] ?? .unreachable(reason: "no stub")
        return PirSnapshotProbeOutcome(url: url, status: status)
    }

    var callsMade: [(url: String, expected: UInt64)] {
        get async { await log.calls }
    }
}

/// Intercepts every HTTP request made through a session configured with
/// `protocolClasses = [StubURLProtocol.self]`, and dispatches it through the
/// per-test `handler` closure. Either return `(statusCode, body)` for a
/// successful response or throw to simulate a transport-layer failure.
private final class StubURLProtocol: URLProtocol {
    nonisolated(unsafe) static var handler: ((URLRequest) throws -> (Int, Data))?

    static func reset() {
        handler = nil
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = StubURLProtocol.handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.unknown))
            return
        }

        do {
            let (status, body) = try handler(request)
            let response = HTTPURLResponse(
                url: request.url ?? URL(string: "about:blank")!,
                statusCode: status,
                httpVersion: "HTTP/1.1",
                headerFields: nil
            )!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: body)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
