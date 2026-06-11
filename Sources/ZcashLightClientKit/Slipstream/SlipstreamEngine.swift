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
    private let server: LightWalletEndpoint

    // ── Init ───────────────────────────────────────────────────────────────────

    public init(dbURL: URL, server: LightWalletEndpoint) {
        self.dbURL = dbURL
        self.server = server
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
                networkId
            )
        }

        guard let newHandle else {
            throw ZcashError.rustSlipstreamOpen(lastErrorMessage(fallback: "`SlipstreamEngine.open` failed with unknown error"))
        }
        handle = newHandle
    }

    /// Starts a sync pass.
    ///
    /// - Parameters:
    ///   - ufvk: optional Unified Full Viewing Key string (UTF-8). When `nil`, the engine performs a
    ///           keyless update — the account must already be imported in data.db via `prepare`.
    ///   - birthday: wallet birthday height (ignored when `ufvk` is nil).
    /// - Throws: `ZcashError.rustSlipstreamNotOpen` if `open` hasn't been called,
    ///           `ZcashError.rustSlipstreamStart` if the Rust call fails.
    public func start(ufvk: String?, birthday: BlockHeight) throws {
        guard let handlePtr = handle else {
            throw ZcashError.rustSlipstreamNotOpen
        }

        let result: Bool
        if let ufvk {
            // Pass UFVK bytes and birthday.  Use Array(ufvk.utf8) → withUnsafeBufferPointer
            // for explicit pointer + length (matches plan C9 correction).
            let ufvkBytes = Array(ufvk.utf8)
            result = ufvkBytes.withUnsafeBufferPointer { ptr in
                zcashlc_slipstream_start(handlePtr, ptr.baseAddress, UInt(ptr.count), UInt64(birthday))
            }
        } else {
            // Keyless update: pass null UFVK pointer with length 0.
            result = zcashlc_slipstream_start(handlePtr, nil, 0, UInt64(birthday))
        }

        guard result else {
            throw ZcashError.rustSlipstreamStart(lastErrorMessage(fallback: "`SlipstreamEngine.start` failed with unknown error"))
        }
    }

    /// Stops the in-flight sync (non-blocking — Rust aborts the tokio task asynchronously).
    /// The handle remains live; poll `snapshot()` to observe the state transition to idle.
    public func stop() {
        guard let handlePtr = handle else { return }
        _ = zcashlc_slipstream_stop(handlePtr)
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
