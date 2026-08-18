//
//  DBActor.swift
//
//
//  Created by Lukáš Korba on 04-08-2024.
//

import Foundation

/// Serializer of Swift-initiated database WRITES — and only that.
///
/// THE RULE (read/write split, 2026-08-03): every method that can write through the FFI or the
/// Swift DAO layer takes `@DBActor`. Genuinely read-only methods do NOT take it; each carries a
/// `// DB-READ (audited <date>): <verified function/SQL> — <reason>` marker naming exactly what
/// was checked. A call whose read-only-ness cannot be positively established stays `@DBActor`
/// with a comment saying so. When the librustzcash pin moves, any FFI function whose Rust body
/// changed needs its classification re-checked before the marker date is trusted.
///
/// The migration read entry points are the exception that needs no re-check: they open through
/// the FFI's `open_read` (SQLITE_OPEN_READ_ONLY on both connections), so their read-only-ness
/// is enforced by SQLite itself, not by audit.
///
/// WHAT THIS ACTOR GUARANTEES: no two Swift-initiated writes ever interleave.
///
/// WHAT IT DOES NOT AND CANNOT GUARANTEE: the slipstream engine writes to the same database
/// files from Rust-managed threads continuously, outside any Swift actor — Swift-side
/// serialization has never covered it. Nor does the actor provide cross-call snapshot
/// consistency: every FFI call opens its own connection and sees its own WAL snapshot. Data
/// safety below the actor is per-call connections + WAL + the 15-second busy_timeout, which is
/// also why long CPU-bound writes (proof generation) are CHUNKED rather than detached: the
/// actor holds through each chunk on purpose — writers queue, readers (off-actor) do not.
@globalActor
enum DBActor {
    typealias ActorType = Actor

    actor Actor { }
    static let shared = Actor()

    static var sharedUnownedExecutor: UnownedSerialExecutor {
        shared.unownedExecutor
    }
}
