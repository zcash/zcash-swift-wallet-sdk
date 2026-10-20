// PirSnapshotResolver.swift
// Filters PIR endpoints by snapshot match before delegation proofing.
//
// Wallet clients receive a list of PIR endpoints in the voting service config
// alongside an `expected snapshot height` for the active round. This resolver
// assumes those endpoints expose the vote-nullifier-pir `/root` API
// (https://github.com/valargroup/vote-nullifier-pir), where `RootInfo.height`
// reports the served snapshot height. The delegation proof is bound to the
// round's snapshot, so a PIR server serving any other snapshot — whether behind
// (still catching up) or ahead (already moved past the round's snapshot) —
// would answer nullifier-non-membership queries against the wrong tree and
// produce a proof the chain rejects.
//
// To avoid that, the resolver probes every configured endpoint and randomly
// selects one whose served height is exactly equal to `expectedSnapshotHeight`.
// Endpoints that are missing snapshot metadata, unreachable, or report any
// other height are excluded. If no endpoint matches, `resolve(...)` throws —
// the SDK refuses to proceed instead of falling back to a mismatched server.

import Foundation

/// Errors produced while selecting a PIR endpoint.
public enum PirSnapshotResolverError: LocalizedError, Equatable {
    /// `pir_endpoints` was empty in the wallet config.
    case noEndpointsConfigured
    /// Every probed endpoint was unreachable, malformed, or reported a snapshot
    /// height different from `expectedSnapshotHeight` (either behind or ahead).
    /// `details` is a per-endpoint summary for diagnostics.
    case noMatchingEndpoint(expected: BlockHeight, details: [PirSnapshotProbeOutcome])

    public var errorDescription: String? {
        switch self {
        case .noEndpointsConfigured:
            return "No PIR endpoints are configured."
        case let .noMatchingEndpoint(expected, details):
            let summary = details.map(\.shortDescription).joined(separator: "; ")
            let lead = "No PIR server matches the round's expected snapshot height \(expected)."
            let tail = "Voting cannot proceed until a PIR server reports the matching snapshot. [\(summary)]"
            return "\(lead) \(tail)"
        }
    }
}

/// Outcome of probing a single PIR endpoint.
public struct PirSnapshotProbeOutcome: Equatable, Sendable {
    public enum Status: Equatable, Sendable {
        /// Endpoint reported a snapshot height that matches the expected snapshot exactly.
        case matching(height: BlockHeight)
        /// Endpoint reported a snapshot height that is not equal to the expected snapshot
        /// (either behind or ahead).
        case mismatched(height: BlockHeight)
        /// Endpoint returned a response without a usable height field.
        case missingHeight
        /// Endpoint failed to respond, returned non-200, or the response could not be parsed.
        case unreachable(reason: String)
    }

    public let url: String
    public let status: Status

    public init(url: String, status: Status) {
        self.url = url
        self.status = status
    }

    /// Compact description for logs / aggregated error messages.
    public var shortDescription: String {
        switch status {
        case .matching(let height):
            return "\(url): matching@\(height)"
        case .mismatched(let height):
            return "\(url): mismatched@\(height)"
        case .missingHeight:
            return "\(url): missing-height"
        case .unreachable(let reason):
            return "\(url): unreachable(\(reason))"
        }
    }
}

/// Probes a single PIR endpoint's `/root` and reports its snapshot status.
///
/// Returning a `PirSnapshotProbeOutcome` (rather than throwing) lets the
/// resolver collect per-endpoint diagnostics across the whole list before
/// deciding to fail.
public protocol PirSnapshotProbing: Sendable {
    func probe(url: String, expectedSnapshotHeight: BlockHeight) async -> PirSnapshotProbeOutcome
}

/// Selects a PIR endpoint whose served snapshot height equals `expectedSnapshotHeight` exactly.
public struct PirSnapshotResolver: Sendable {
    private let probe: PirSnapshotProbing
    private let matchingEndpointSelector: @Sendable ([PirSnapshotProbeOutcome]) -> PirSnapshotProbeOutcome?

    public init(probe: PirSnapshotProbing = HTTPPirSnapshotProbe()) {
        self.probe = probe
        matchingEndpointSelector = { $0.randomElement() }
    }

    init(
        probe: PirSnapshotProbing,
        matchingEndpointSelector: @escaping @Sendable ([PirSnapshotProbeOutcome]) -> PirSnapshotProbeOutcome?
    ) {
        self.probe = probe
        self.matchingEndpointSelector = matchingEndpointSelector
    }

    /// Probe all `endpoints` in parallel and return a randomly selected URL
    /// whose served snapshot height equals `expectedSnapshotHeight` exactly.
    ///
    /// Strict equality — not `>=` — because the delegation proof is bound to the
    /// round's specific snapshot. A PIR server serving a different snapshot
    /// (behind or ahead) answers nullifier queries against the wrong tree and
    /// would produce a proof the chain rejects.
    ///
    /// Throws `PirSnapshotResolverError.noEndpointsConfigured` if `endpoints` is empty,
    /// or `.noMatchingEndpoint(...)` if every endpoint reports a non-matching height,
    /// is missing metadata, or is unreachable.
    public func resolve(
        endpoints: [String],
        expectedSnapshotHeight: BlockHeight
    ) async throws -> String {
        guard !endpoints.isEmpty else {
            throw PirSnapshotResolverError.noEndpointsConfigured
        }

        let outcomes = await withTaskGroup(of: (Int, PirSnapshotProbeOutcome).self) { group in
            for (index, url) in endpoints.enumerated() {
                group.addTask {
                    let outcome = await probe.probe(
                        url: url,
                        expectedSnapshotHeight: expectedSnapshotHeight
                    )
                    return (index, outcome)
                }
            }
            // Preserve input order for stable diagnostics when no endpoint matches.
            var collected: [(Int, PirSnapshotProbeOutcome)] = []
            for await item in group {
                collected.append(item)
            }
            collected.sort { $0.0 < $1.0 }
            return collected.map(\.1)
        }

        let matchingOutcomes = outcomes.filter { outcome in
            if case .matching = outcome.status { return true }
            return false
        }
        let chosen = matchingEndpointSelector(matchingOutcomes)

        guard let chosen else {
            throw PirSnapshotResolverError.noMatchingEndpoint(
                expected: expectedSnapshotHeight,
                details: outcomes
            )
        }
        return chosen.url
    }
}

// MARK: - HTTP probe

/// Default probe implementation that calls `GET <url>/root` and parses
/// `vote-nullifier-pir`'s `RootInfo` response.
public struct HTTPPirSnapshotProbe: PirSnapshotProbing {
    private let session: URLSession?
    private let timeout: TimeInterval

    /// - Parameters:
    ///   - session: Optional `URLSession` to reuse. When `nil`, a new session
    ///     is created for each probe, with `timeout` applied to both request
    ///     and (2×) resource timeouts, then invalidated after the probe finishes.
    ///     Pass a custom session in tests; in that case `timeout` is ignored
    ///     because the session already carries its own configuration.
    ///   - timeout: Per-request timeout in seconds for the default session.
    public init(session: URLSession? = nil, timeout: TimeInterval = 5) {
        self.session = session
        self.timeout = timeout
    }

    public func probe(url: String, expectedSnapshotHeight: BlockHeight) async -> PirSnapshotProbeOutcome {
        guard let endpoint = URL(string: "\(url.trimmedTrailingSlash)/root") else {
            return PirSnapshotProbeOutcome(url: url, status: .unreachable(reason: "invalid URL"))
        }

        let ownsSession = session == nil
        let session = session ?? Self.makeSession(timeout: timeout)
        defer {
            if ownsSession {
                session.finishTasksAndInvalidate()
            }
        }

        do {
            let request = URLRequest(
                url: endpoint,
                cachePolicy: .reloadIgnoringLocalCacheData
            )
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                return PirSnapshotProbeOutcome(url: url, status: .unreachable(reason: "non-HTTP response"))
            }
            guard http.statusCode == 200 else {
                return PirSnapshotProbeOutcome(
                    url: url,
                    status: .unreachable(reason: "HTTP \(http.statusCode)")
                )
            }
            let info: RootInfo
            do {
                info = try JSONDecoder().decode(RootInfo.self, from: data)
            } catch {
                return PirSnapshotProbeOutcome(
                    url: url,
                    status: .unreachable(reason: "decode failed: \(error.localizedDescription)")
                )
            }
            guard let height = info.height else {
                return PirSnapshotProbeOutcome(url: url, status: .missingHeight)
            }
            if height == expectedSnapshotHeight {
                return PirSnapshotProbeOutcome(url: url, status: .matching(height: height))
            } else {
                return PirSnapshotProbeOutcome(url: url, status: .mismatched(height: height))
            }
        } catch {
            return PirSnapshotProbeOutcome(
                url: url,
                status: .unreachable(reason: error.localizedDescription)
            )
        }
    }

    /// Wire shape of `GET /root` from `vote-nullifier-pir`. Only `height` is
    /// load-bearing here; the other fields are decoded for forward-compat /
    /// to ensure the response is the right shape.
    private struct RootInfo: Decodable {
        let root29: String?
        let root25: String?
        let numRanges: Int?
        let pirDepth: Int?
        let height: BlockHeight?

        enum CodingKeys: String, CodingKey {
            case root29
            case root25
            case numRanges = "num_ranges"
            case pirDepth = "pir_depth"
            case height
        }
    }

    private static func makeSession(timeout: TimeInterval) -> URLSession {
        let config = URLSessionConfiguration.default
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout * 2
        config.urlCache = nil
        return URLSession(configuration: config)
    }
}

private extension String {
    var trimmedTrailingSlash: String {
        hasSuffix("/") ? String(dropLast()) : self
    }
}
