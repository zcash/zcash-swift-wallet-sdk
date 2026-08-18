//
//  SlipstreamEngine.swift
//  ZcashLightClientKit
//
//  Created for Slipstream task [#1755].
//
//  Swift actor wrapping the Rust Slipstream engine handle.
//  Lifecycle mirrors TorClient (see Tor/TorClient.swift):
//    open  → allocates the opaque SlipstreamHandle (tokio runtime + progress atomics + event ring)
//    start → spawns the sync task inside the Rust runtime
//    stop  → cancels the in-flight sync task (non-blocking abort)
//    deinit→ calls zcashlc_slipstream_free (drops the Rust Box<SlipstreamHandle>)
//

import Foundation
import libzcashlc

// TODO: [#1755] SlipstreamEngine — consider adding reconnect/retry logic once the
//   full T4.4 darkside test suite is green and the server-switch path is wired up.

/// Swift actor wrapping the Rust Slipstream engine handle.
/// All calls into the C FFI surface are serialised by the actor's executor.
public actor SlipstreamEngine {
    // ── Storage ────────────────────────────────────────────────────────────────
    private var handle: OpaquePointer?
    private let dbURL: URL
    // `server` is mutable so `switchTo(endpoint:)` can re-open the handle against
    // a different endpoint without constructing a new engine actor.
    private var server: LightWalletEndpoint
    // [v0.7 P1b] Alternate servers for the engine's probe-then-commit + wire
    // failover. Pushed onto the handle by `open()` — the ONE place, so a
    // `reopen()` (switchTo) re-applies them to the fresh handle automatically;
    // `setAlternates` replaces the list at runtime (user consent toggles).
    // The full host list is fine here: the Rust side dedupes against whatever
    // the primary is at each start().
    private var alternates: [LightWalletEndpoint]

    // ── Init ───────────────────────────────────────────────────────────────────

    public init(dbURL: URL, server: LightWalletEndpoint, alternates: [LightWalletEndpoint] = []) {
        self.dbURL = dbURL
        self.server = server
        self.alternates = alternates
    }

    // ── deinit ─────────────────────────────────────────────────────────────────
    // nonisolated deinit is required by Swift actor rules.
    // Capture the pointer before deinit; free it outside the actor (TorClient precedent).

    deinit {
        guard let handlePtr = handle else { return }
        zcashlc_slipstream_free(handlePtr)
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    /// Opens the engine handle (idempotent — no-op if already open).
    /// Must be called before `start`.
    ///
    /// - Parameter network: the Zcash network (mainnet or testnet).
    /// - Throws: `ZcashError.rustSlipstreamOpen` if the Rust call fails.
    public func open(network: ZcashNetwork) throws {
        guard handle == nil else { return }

        // Use osPathStr() (filesystem path, not URL string) — same as ZcashRustBackend.swift:105.
        // Swift bridges (String, UInt) → (const uint8_t *, uintptr_t) implicitly (UTF-8 C string).
        let dbData = dbURL.osPathStr()
        let hostData = Array(server.host.utf8)
        let networkId: UInt32 = network.networkType == .mainnet ? 1 : 0

        let newHandle: OpaquePointer? = hostData.withUnsafeBufferPointer { hPtr in
            zcashlc_slipstream_open(
                dbData.0,
                dbData.1,
                hPtr.baseAddress,
                UInt(hPtr.count),
                UInt16(clamping: server.port),
                server.secure,
                networkId,
                // T8.4: device-memory hint — the Rust side derates fetch/split budgets on
                // <3 GiB devices (A10-class) so spam-era restores don't jetsam. 0 = unknown.
                ProcessInfo.processInfo.physicalMemory
            )
        }

        guard let newHandle else {
            throw ZcashError.rustSlipstreamOpen(lastErrorMessage(fallback: "`SlipstreamEngine.open` failed with unknown error"))
        }
        handle = newHandle

        // [v0.7 P1b] Push the alternate-server list onto the fresh handle: every
        // subsequent start() merges it into the pass config (probe-then-commit +
        // mid-pass wire failover; Tor passes ignore it engine-side).
        pushAlternates(to: newHandle)
    }

    /// [v0.7 P1b] Replaces the alternate-server list. Takes effect from the NEXT
    /// sync pass — an in-flight pass keeps the config it started with. An empty
    /// list restores exact single-server behavior (probe skipped, failover
    /// disarmed): this is how the host revokes consent (e.g. the user switches
    /// server selection from Automatic to Manual).
    public func setAlternates(_ endpoints: [LightWalletEndpoint]) {
        alternates = endpoints
        if let handlePtr = handle {
            pushAlternates(to: handlePtr)
        }
    }

    /// Writes `alternates` to the Rust handle (empty list clears it). Best-effort —
    /// alternates are an optimization, never a reason to fail open(). The URIs are
    /// constructed from typed endpoints, so a parse rejection Rust-side is a
    /// programming error, not a runtime condition.
    private func pushAlternates(to handlePtr: OpaquePointer) {
        let uris = alternates
            .map { "\($0.secure ? "https" : "http")://\($0.host):\($0.port)" }
            .joined(separator: "\n")
        let uriBytes = Array(uris.utf8)
        let accepted = uriBytes.withUnsafeBufferPointer { ptr in
            zcashlc_slipstream_set_alternate_servers(
                handlePtr,
                uriBytes.isEmpty ? nil : ptr.baseAddress,
                UInt(ptr.count)
            )
        }
        assert(accepted, "alternate-server URIs rejected: \(lastErrorMessage(fallback: "unknown"))")
    }

    /// Starts a sync pass.
    ///
    /// - Parameters:
    ///   - ufvk: optional Unified Full Viewing Key string (UTF-8). When `nil`, the engine performs a
    ///           keyless update — the account must already be imported in data.db via `prepare`.
    ///   - birthday: wallet birthday height (ignored when `ufvk` is nil).
    /// - Throws: `ZcashError.rustSlipstreamNotOpen` if `open` hasn't been called,
    ///           `ZcashError.rustSlipstreamStart` if the Rust call fails.
    /// T-Tor.3: `torDir` is a dedicated Tor state directory for the engine's isolated
    /// circuits, passed ONLY when Tor is enabled (`nil` = direct, no Tor). It must be
    /// SEPARATE from the old SDK's `TorClient` directory (arti holds a state lock).
    /// (The engine mirrors the old SDK's per-platform `dangerously_trust_everyone` internally.)
    public func start(ufvk: String?, birthday: BlockHeight, torDir: String?) async throws {
        guard let handlePtr = handle else {
            throw ZcashError.rustSlipstreamNotOpen
        }

        // Empty Tor-dir bytes → null pointer / length 0 → the engine syncs directly (Tor off).
        let torBytes: [UInt8] = torDir.map { Array($0.utf8) } ?? []
        let ufvkBytes: [UInt8]? = ufvk.map { Array($0.utf8) }
        // [B4-16 drain] The FFI now DRAINS the aborted pass's in-flight write-behind
        // commit (bounded ≤10 s) before spawning the new session — a real wait, so hop
        // off the cooperative pool (same pattern as restoreAnchor).
        let result: Bool = await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let ok: Bool = torBytes.withUnsafeBufferPointer { torPtr in
                    let torBase = torPtr.baseAddress
                    let torLen = UInt(torPtr.count)
                    if let ufvkBytes {
                        // Pass UFVK bytes and birthday.  Use Array(ufvk.utf8) →
                        // withUnsafeBufferPointer for explicit pointer + length
                        // (matches plan C9 correction).
                        return ufvkBytes.withUnsafeBufferPointer { ptr in
                            zcashlc_slipstream_start(handlePtr, ptr.baseAddress, UInt(ptr.count), UInt64(birthday), torBase, torLen)
                        }
                    } else {
                        // Keyless update: pass null UFVK pointer with length 0.
                        return zcashlc_slipstream_start(handlePtr, nil, 0, UInt64(birthday), torBase, torLen)
                    }
                }
                continuation.resume(returning: ok)
            }
        }

        guard result else {
            throw ZcashError.rustSlipstreamStart(lastErrorMessage(fallback: "`SlipstreamEngine.start` failed with unknown error"))
        }
    }

    /// Stops the in-flight sync AND drains the engine's in-flight wallet commit
    /// ([B4-16] — `abort()` cannot cancel a `spawn_blocking` write-behind commit, so the
    /// FFI now blocks, bounded ≤10 s, until the wallet file is quiescent). A returned
    /// stop() is the contract deleteAccount/importAccount/rewind serialize on: their
    /// wallet write can no longer interleave with an orphan commit. Hopped off the
    /// cooperative pool — the drain is a real wait; never block an actor thread.
    public func stop() async {
        guard let handlePtr = handle else { return }
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                _ = zcashlc_slipstream_stop(handlePtr)
                continuation.resume()
            }
        }
    }

    /// [Engine API v2 §4.5] Tells the engine the HOST changed the wallet's transaction set
    /// outside a sync pass (a just-broadcast transaction was stored). The engine emits a
    /// FoundTransactions event through its normal channel, so the poll loop surfaces the
    /// pending transaction on the next tick — uniformly for every host. No-op on a nil handle.
    public func notifyTxChange() {
        guard let handlePtr = handle else { return }
        _ = zcashlc_slipstream_notify_tx_change(handlePtr)
    }

    /// Frees the engine handle exactly once and nils the pointer.
    ///
    /// Called by `wipe()` so the Rust-side tokio runtime and all associated state are
    /// released before the on-disk database files are deleted.  `deinit` checks for a
    /// nil handle to avoid a double-free.
    ///
    /// - Note: idempotent — safe to call even if the engine was never opened.
    public func close() {
        guard let handlePtr = handle else { return }
        zcashlc_slipstream_free(handlePtr)
        handle = nil
    }

    /// Closes the current handle (if any) and opens a new one bound to `newServer`.
    ///
    /// Used by `SlipstreamSynchronizer.switchTo(endpoint:)`.  The caller is
    /// responsible for stopping any in-flight sync before calling this method.
    ///
    /// - Parameters:
    ///   - newServer: the replacement `LightWalletEndpoint`.
    ///   - network:   the Zcash network (unchanged across switches).
    /// - Throws: `ZcashError.rustSlipstreamOpen` if the re-open fails.
    public func reopen(server newServer: LightWalletEndpoint, network: ZcashNetwork) throws {
        // Free the old handle (exact-once guard already inside close()).
        close()
        // Store the new endpoint so subsequent open/start calls use it.
        server = newServer
        // Open a fresh handle bound to the new endpoint.
        try open(network: network)
    }

    /// [Engine API v2 §0.5 / v2.1 Phase 1] The unified, PHASE-RESOLVING wallet summary:
    /// one call that is correct at every phase — recovering ⇒ the upstream summary with
    /// per-account balances REPLACED by `ext_slipstream_v_recovery_balance` (Σ of final,
    /// reconciled tx deltas — never over-shows); not recovering ⇒ the upstream summary
    /// passed through unchanged. No host ever re-implements restore balance math.
    ///
    /// Returns `nil` when the engine is not open, the call fails, or the wallet has no
    /// balance data yet (the FFI "none" summary).
    ///
    /// COST + THREADING: the FFI rations the walk internally (E-1), so this is freely
    /// callable per poll tick — every call serves the cached summary (including a cached
    /// "none" / no-balance-data-yet summary), and refreshes run on a background thread at
    /// range/state boundaries or after a 2 s idle TTL. Synchronous cost on this actor is
    /// limited to two cases: the FIRST call on a handle (the cache prime — hosts do it at
    /// prepare/open time, a quiet state), and, during recovery, a bounded (~250 ms
    /// worst-case) recovery-balance view read that falls back to the last-good nets on
    /// contention. It still runs on THIS actor deliberately — that serializes it with
    /// `close()`, making use-after-free impossible.
    /// (Internal because `WalletSummary` is an internal model — the synchronizer is the consumer.)
    func walletSummary(
        confirmationsPolicy: ConfirmationsPolicy = ConfirmationsPolicy.defaultTransferPolicy()
    ) -> WalletSummary? {
        guard let handlePtr = handle else { return nil }
        guard let summaryPtr = zcashlc_slipstream_wallet_summary(handlePtr, confirmationsPolicy.toBackend()) else {
            return nil
        }
        defer { zcashlc_free_wallet_summary(summaryPtr) }
        return WalletSummary.fromFFI(summaryPtr)
    }

    // ── Poll surface (D8) ──────────────────────────────────────────────────────

    /// Returns a snapshot of current progress counters (non-blocking).
    /// Returns `nil` when the engine is not yet open.
    public func snapshot() -> SlipstreamSnapshot? {
        guard let handlePtr = handle else { return nil }
        // zcashlc_slipstream_snapshot returns FfiSlipstreamSnapshot BY VALUE.
        let cSnapshot = zcashlc_slipstream_snapshot(handlePtr)
        return SlipstreamSnapshot(cSnapshot)
    }

    /// Drains queued events from the Rust event ring (non-blocking).
    /// Returns up to `capacity` events (EVENT_RING_CAP = 64 in Rust).
    ///
    /// - Parameter capacity: maximum events to drain (defaults to 64 matching `EVENT_RING_CAP`).
    public func drainEvents(capacity: Int = 64) -> [SlipstreamEngineEvent] {
        guard let handlePtr = handle else { return [] }
        var buf = [FfiSlipstreamEvent](
            repeating: FfiSlipstreamEvent(tag: 0, value: 0),
            count: capacity
        )
        let count = zcashlc_slipstream_drain_events(handlePtr, &buf, UInt(capacity))
        return buf.prefix(Int(count)).map { SlipstreamEngineEvent(tag: $0.tag, value: $0.value) }
    }
}

// MARK: - Wallet-provisioning anchor (v2.1 E-6, handle-less)

/// [E-6] The engine-resolved wallet-provisioning anchor. RESTORE: `height` = the
/// recover_until to provision (always valid — live tip, or the engine's offline
/// `max(bundled checkpoint, birthday+1)` fallback), `treeState` nil (the host keeps its
/// birthday checkpoint). NEW: the reorg-safe recent server tree state, or nil when
/// offline (the host keeps its bundled checkpoint defaults).
struct SlipstreamRestoreAnchor {
    let height: BlockHeight
    let treeState: TreeState?
}

extension SlipstreamEngine {
    /// [E-6] Resolve the provisioning anchor via `zcashlc_slipstream_restore_anchor` —
    /// HANDLE-LESS (provisioning runs before `open()`, and `importAccount` must not
    /// serialize against the live handle), so this is a static member. The FFI blocks for
    /// the round-trip (single direct attempt; bounded Tor circuit retries when `torDirPath`
    /// is set — a failed Tor bootstrap resolves OFFLINE, never a direct fallback), so the
    /// call is hopped off the cooperative pool.
    // swiftlint:disable:next function_parameter_count
    static func restoreAnchor(
        isRestore: Bool,
        birthday: BlockHeight,
        fallbackCheckpointHeight: BlockHeight,
        server: LightWalletEndpoint,
        network: ZcashNetwork,
        torDirPath: String?
    ) async -> SlipstreamRestoreAnchor? {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: restoreAnchorBlocking(
                    isRestore: isRestore,
                    birthday: birthday,
                    fallbackCheckpointHeight: fallbackCheckpointHeight,
                    server: server,
                    network: network,
                    torDirPath: torDirPath
                ))
            }
        }
    }

    // swiftlint:disable:next function_parameter_count
    private static func restoreAnchorBlocking(
        isRestore: Bool,
        birthday: BlockHeight,
        fallbackCheckpointHeight: BlockHeight,
        server: LightWalletEndpoint,
        network: ZcashNetwork,
        torDirPath: String?
    ) -> SlipstreamRestoreAnchor? {
        let hostData = Array(server.host.utf8)
        let torData = Array((torDirPath ?? "").utf8)
        let networkId: UInt32 = network.networkType == .mainnet ? 1 : 0

        let anchorPtr: UnsafeMutablePointer<FfiRestoreAnchor>? = hostData.withUnsafeBufferPointer { hPtr in
            torData.withUnsafeBufferPointer { tPtr in
                zcashlc_slipstream_restore_anchor(
                    hPtr.baseAddress,
                    UInt(hPtr.count),
                    UInt16(clamping: server.port),
                    server.secure,
                    networkId,
                    isRestore ? 1 : 0,
                    UInt64(birthday),
                    UInt64(fallbackCheckpointHeight),
                    torData.isEmpty ? nil : tPtr.baseAddress,
                    UInt(torData.count)
                )
            }
        }
        guard let anchorPtr else { return nil }
        defer { zcashlc_slipstream_free_restore_anchor(anchorPtr) }

        var treeState: TreeState?
        if let tsPtr = anchorPtr.pointee.treestate, anchorPtr.pointee.treestate_len > 0 {
            let data = Data(bytes: tsPtr, count: Int(anchorPtr.pointee.treestate_len))
            treeState = try? TreeState(serializedBytes: data)
        }
        return SlipstreamRestoreAnchor(
            height: BlockHeight(anchorPtr.pointee.height),
            treeState: treeState
        )
    }
}
