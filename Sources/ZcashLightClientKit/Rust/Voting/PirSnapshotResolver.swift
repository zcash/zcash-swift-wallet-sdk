// PirSnapshotResolver.swift
// Filters PIR endpoints by snapshot match before delegation proofing.
//
// Wallet clients receive a list of PIR endpoints in the voting service config
// alongside an `expected snapshot height` for the active round. PIR servers
// publish their served snapshot height via `GET /root` (`RootInfo.height`,
// see vote-nullifier-pir/pir/types). The delegation proof is bound to the
// round's snapshot, so a PIR server serving any other snapshot — whether
// behind (still catching up) or ahead (already moved past the round's
// snapshot) — would answer nullifier-non-membership queries against the
// wrong tree and produce a proof the chain rejects.
//
// To avoid that, the resolver probes every configured endpoint and selects
// the first one whose served height is exactly equal to `expectedSnapshotHeight`,
// in config order. Endpoints that are missing snapshot metadata, unreachable,
// or report any other height are excluded. If no endpoint matches,
// `resolve(...)` throws — the SDK refuses to proceed instead of falling back
// to a mismatched server (per ZCA-229).

import Foundation

/// Errors produced while selecting a PIR endpoint.
public enum PirSnapshotResolverError: LocalizedError, Equatable {
    /// `pir_endpoints` was empty in the wallet config.
    case noEndpointsConfigured
    /// Every probed endpoint was unreachable, malformed, or reported a snapshot
    /// height different from `expectedSnapshotHeight` (either behind or ahead).
    /// `details` is a per-endpoint summary for diagnostics.
    case noMatchingEndpoint(expected: UInt64, details: [PirSnapshotProbeOutcome])

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
        case matching(height: UInt64)
        /// Endpoint reported a snapshot height that is not equal to the expected snapshot
        /// (either behind or ahead).
        case mismatched(height: UInt64)
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
    func probe(url: String, expectedSnapshotHeight: UInt64) async -> PirSnapshotProbeOutcome
}

/// Selects a PIR endpoint whose served snapshot height equals `expectedSnapshotHeight` exactly.
public struct PirSnapshotResolver: Sendable {
    private let probe: PirSnapshotProbing

    public init(probe: PirSnapshotProbing = HTTPPirSnapshotProbe()) {
        self.probe = probe
    }

    /// Probe all `endpoints` in parallel and return the first URL (in config order)
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
        expectedSnapshotHeight: UInt64
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
            // Preserve input order so endpoint priority (config order) is kept
            // when multiple endpoints match.
            var collected: [(Int, PirSnapshotProbeOutcome)] = []
            for await item in group {
                collected.append(item)
            }
            collected.sort { $0.0 < $1.0 }
            return collected.map(\.1)
        }

        // All matching endpoints share the same height (= expected) by definition,
        // so we just pick the first one in config order.
        let chosen = outcomes.first { outcome in
            if case .matching = outcome.status { return true }
            return false
        }

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
    private let session: URLSession

    /// - Parameters:
    ///   - session: Optional `URLSession` to reuse. When `nil`, a new session
    ///     is created with `timeout` applied to both request and (2×) resource
    ///     timeouts. Pass a custom session in tests; in that case `timeout` is
    ///     ignored because the session already carries its own configuration.
    ///   - timeout: Per-request timeout in seconds for the default session.
    public init(session: URLSession? = nil, timeout: TimeInterval = 5) {
        if let session {
            self.session = session
        } else {
            let config = URLSessionConfiguration.default
            config.timeoutIntervalForRequest = timeout
            config.timeoutIntervalForResource = timeout * 2
            self.session = URLSession(configuration: config)
        }
    }

    public func probe(url: String, expectedSnapshotHeight: UInt64) async -> PirSnapshotProbeOutcome {
        guard let endpoint = URL(string: "\(url.trimmedTrailingSlash)/root") else {
            return PirSnapshotProbeOutcome(url: url, status: .unreachable(reason: "invalid URL"))
        }

        do {
            let (data, response) = try await session.data(from: endpoint)
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
        let height: UInt64?

        enum CodingKeys: String, CodingKey {
            case root29
            case root25
            case numRanges = "num_ranges"
            case pirDepth = "pir_depth"
            case height
        }
    }
}

private extension String {
    var trimmedTrailingSlash: String {
        hasSuffix("/") ? String(dropLast()) : self
    }
}
