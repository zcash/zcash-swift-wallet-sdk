//
//  MigrationModels.swift
//  ZcashLightClientKit
//

import Foundation

/// The migration engine's next-step decision for the stored Orchard -> Ironwood run, as surfaced
/// by `Synchronizer.migrationAdvanceStep(accountUUID:)` /
/// `ZcashRustBackendWelding.migrationAdvanceStep(for:)`.
///
/// A conduit of the upstream engine's public `advance_migration` API: every upstream case
/// marshals onto its own case here — ``replan`` and ``reevaluate`` included, bare, exactly as
/// upstream carries them. (The interim `requiresAttention(id:)` collapse, which folded both
/// behind one synthesised transaction id, is retired — 2026-08-08.)
/// `nil` at the API level (the call returns an optional) means no migration run is stored at all —
/// none was ever committed for the account — so there is nothing to advance and nothing to poll.
/// The engine's priority order: ``reevaluate`` outranks everything (an open rejection report
/// freezes adjudication until the scan catches up), ``replan`` ends the drive until the user
/// re-plans, and a proven, due transaction broadcasts ahead of any new proving work (its
/// broadcast window is the scarcer resource; proving can happen on any later wake-up).
///
/// Evaluated with both the wallet's fully-scanned target and its wall-clock tip estimate. Upstream
/// uses the estimate only for reversible scheduling/withholding; persisted or destructive
/// judgments remain anchored to scanned data. It is also memoryless about sessions: it reports
/// what the run needs next, not whether doing it now would pair a broadcast
/// with a sync — session policy (one broadcast per session, no sync in a broadcast session)
/// belongs to the caller and the sync gate, not to this value.
///
/// Discharging each step:
/// - ``reevaluate`` → SYNC (to at least the tip the rejecting node reported), then call
///   `migrationAdvanceStep(accountUUID:)` again: the engine adjudicates against the newly scanned
///   data and, where the rejection was transient, re-offers the work in that same call. Not a
///   user-facing state — the run is alive and nothing is asked of anyone but the syncer.
/// - ``replan`` → the run is finished deciding and is not driven further: surface the re-plan UX
///   over the ``MigrationTransactionStatus/State/invalid(reason:)`` row(s), then
///   `restartCurrentMigrationStep(accountUUID:)` to cancel and re-plan. No sync first — the
///   verdict is already persisted and cannot be scanned away.
/// - ``broadcast(_:)`` → `performMigrationBroadcast(accountUUID:_:options:)`: hand the case's
///   opaque ``MigrationBroadcastInstruction`` straight to the executor and end the session — a
///   broadcast session must not sync.
/// - ``prove(transactions:)`` → the WHOLE batch is ready, and the batch IS the instruction: hand
///   it to `proveMigrationTransactions(accountUUID:_:maxProofs:)` at a sync wake-up (see
///   `migrationSyncWakeups(accountUUID:)`), which proves up to the caller's budget from that pass. Each
///   entry's ``MigrationProveTarget/kind`` distinguishes what follows for THAT transaction: a
///   ``MigrationTransactionStatus/Kind/transfer(crossing:)`` entry's broadcast follows in its own
///   LATER session — proving has no deadline of its own, a transfer's boundary anchor checkpoint
///   is durably retained, so a missed wake-up defers the proof, never invalidates it — while a
///   ``MigrationTransactionStatus/Kind/preparation(layer:index:)`` entry is due by construction
///   (the engine only reports a preparation prove once its broadcast height has arrived and its
///   dependencies are mined) and proves against a near-tip witnessable anchor rather than a drawn
///   boundary, so it may broadcast at the SAME wake-up. Broadcast itself remains a separate later
///   step, served one transaction at a time.
/// - ``rebuild(id:)`` → `refreshStaleMigrationTransfers(accountUUID:usk:)` — needs spend
///   authority (a spending key in-process, or the external-signer re-serve ceremony).
/// - ``waiting`` → nothing is actionable now: register OS wake-ups at the heights
///   `migrationSyncWakeups(accountUUID:)` returns, plus each status row's
///   ``MigrationTransactionStatus/scheduledHeight`` for the broadcast windows.
///
/// ``complete`` is terminal for the STORED run — including a CANCELLED one, which the engine also
/// reports as complete rather than ever driving it further — and means "stop polling this run".
/// Per-run, not per-account: whether a migratable balance remains (several successive runs, or
/// funds received later) is answered by `proposeMigrationTransfers(accountUUID:)` — an empty
/// schedule means no.
public enum MigrationAdvanceStep: Equatable, Sendable {
    /// The WHOLE provable set is ready to be proved in one synced session (upstream #2939):
    /// earliest-ready first, never empty, preparations and transfers possibly mixed. Proving
    /// emits nothing on-chain, so nothing is gained by leaving provable work on the table while
    /// a synced session is open — hand the entire batch to
    /// `proveMigrationTransactions(accountUUID:_:maxProofs:)`, which proves as much of it as the
    /// caller's budget allows. Broadcast remains a separate later step, served one transaction at
    /// a time.
    ///
    /// The batch is also the INSTRUCTION: ``MigrationProveTarget`` has no public initializer, so
    /// the only way to hold one is to have cranked `migrationAdvanceStep(accountUUID:)` and been
    /// handed this step.
    case prove(transactions: [MigrationProveTarget])
    /// A proved, due transaction is ready to broadcast: hand the payload to
    /// `performMigrationBroadcast(accountUUID:_:options:)` (and end the session).
    ///
    /// The payload is the opaque ``MigrationBroadcastInstruction`` rather than a bare id: holding
    /// one is the proof that this crank issued the instruction (see that type's doc).
    case broadcast(MigrationBroadcastInstruction)
    /// The transfer identified by `id` expired unmined and must be rebuilt in place.
    case rebuild(id: UInt32)
    /// Nothing is actionable right now: wake again at the sync-wakeup/scheduled heights.
    case waiting
    /// The stored run is terminal (fully mined, or cancelled): stop polling it.
    case complete
    /// The PLAN needs replacing: the run's unsatisfiable share passed the engine's committed
    /// replan threshold, or dead value would otherwise be stranded — an ORDINARY outcome (most
    /// often an ordinary wallet spend consuming notes the plan had allocated), and a verdict the
    /// engine has ALREADY persisted, so more scanning cannot change it. Names no transaction: the
    /// verdict is about the run. See the type doc's discharge mapping.
    case replan
    /// A broadcast this wallet made was REJECTED by a node whose chain view is ahead of this
    /// wallet's scan, and the engine will not adjudicate on stale data. Names no transaction and
    /// asks for nothing but a sync; the engine keeps answering this until the scan reaches the
    /// tip the rejecting node reported. See the type doc's discharge mapping.
    case reevaluate
}

/// The drive's instruction to broadcast one transaction — the payload of
/// ``MigrationAdvanceStep/broadcast(_:)``, and the only thing
/// `performMigrationBroadcast(accountUUID:_:options:)` accepts.
///
/// OPAQUE BY CONSTRUCTION: it has no public initializer, so an app cannot manufacture one. The
/// only way to hold an instruction is to have called `migrationAdvanceStep(accountUUID:)` and been
/// handed it, which is what makes "broadcast a migration transaction the drive did not ask for"
/// unrepresentable at the Swift surface: the app is provided with no capability for semantic
/// migration goals of its own.
///
/// The ``id`` is readable — a host correlates it with a
/// ``MigrationTransactionStatus`` row for display and logging — but reading an id is not a
/// capability: nothing consumes a bare `UInt32`.
///
/// - Important: This is a SWIFT-SURFACE property, not a security boundary. At the C ABI everything
///   is forgeable, and the Rust executors' per-row state gating (a non-`Proved` row is refused)
///   remains the actual safety backstop. The instruction type makes the correct call shape the
///   only one that compiles; it does not make the incorrect one impossible.
public struct MigrationBroadcastInstruction: Equatable, Sendable {
    /// The engine's stable transaction id for the transaction to broadcast — for correlating with
    /// ``MigrationTransactionStatus/id`` and for logging.
    public let id: UInt32

    /// Creates an instruction. SPI(Testing) by design: instructions are produced only by the
    /// advance marshaling (`FfiMigrationAdvanceStep.unsafeToMigrationAdvance()`), and a plain
    /// `import ZcashLightClientKit` cannot name this initializer — possession of an instruction
    /// proves the caller cranked. TEST targets (the SDK's own, and downstream apps') opt in with
    /// `@_spi(Testing) import ZcashLightClientKit`: the SPI name is the ceremony that keeps the
    /// capability boundary greppable and deliberate rather than ambient, and it must never
    /// appear in a production import.
    ///
    /// Written out rather than left to synthesis: the access level IS the capability discipline,
    /// and this declaration is where it is stated and documented. Widening it without the SPI
    /// attribute would silently make instructions forgeable.
    @_spi(Testing) public init(id: UInt32) {
        self.id = id
    }
}

/// One transaction of a ``MigrationAdvanceStep/prove(transactions:)`` batch: the transaction to
/// prove, with the kind that routes it, plus whether its broadcast window has already opened. A
/// preparation may prove and broadcast at the same wake-up; a transfer proves now and broadcasts
/// in its own later session (see the type doc's discharge mapping).
///
/// ``id`` and ``kind`` are a verbatim marshal of the upstream engine's `ProveTarget`;
/// ``isScheduleDue`` is NOT an upstream field but the SDK's own reading of the row against the
/// same dueness targets the advance that produced the batch judged with.
///
/// OPAQUE BY CONSTRUCTION, exactly as ``MigrationBroadcastInstruction`` is: the initializer is
/// internal, so the batch an app holds can only be one the drive handed it. A `[MigrationProveTarget]`
/// IS the prove instruction — see `proveMigrationTransactions(accountUUID:_:maxProofs:)`.
public struct MigrationProveTarget: Equatable, Sendable {
    /// The engine's stable transaction id.
    public let id: UInt32
    /// The preparation/transfer distinction, with its payload.
    public let kind: MigrationTransactionStatus.Kind
    /// Whether the schedule has already reached this transaction's broadcast window — i.e. whether
    /// its missing proof is what stands between the run and a broadcast that could otherwise be
    /// made right now.
    ///
    /// A transaction becomes provable long BEFORE it comes due — that head start is the whole
    /// point of the prove/broadcast split — so most of a batch is ordinarily `false`, meaning
    /// "proving is opportunistic work for the next sync wake-up". A `true` entry means the
    /// schedule has already reached that row: its missing proof is what stands between the run and
    /// a broadcast, so a host with a proof budget to spend has a reason to spend it NOW and crank
    /// again rather than wait for the next wake-up. Informational either way — the batch is
    /// discharged whole, and the engine, not the host, decides what a later crank offers.
    ///
    /// Unlike ``id`` and ``kind`` this is not an upstream `ProveTarget` field but the SDK's
    /// reading of the row against the same dueness targets the advance judged with.
    public let isScheduleDue: Bool

    /// Creates a `MigrationProveTarget`. SPI(Testing) by design: prove targets are produced only
    /// by the advance marshaling (`FfiMigrationAdvanceStep.unsafeToMigrationAdvance()`), and a
    /// plain import cannot name this initializer. Test targets opt in with
    /// `@_spi(Testing) import ZcashLightClientKit` — the ceremony import that must never appear
    /// in production code; see ``MigrationBroadcastInstruction/init(id:)`` for the full rationale.
    @_spi(Testing) public init(id: UInt32, kind: MigrationTransactionStatus.Kind, isScheduleDue: Bool = false) {
        self.id = id
        self.kind = kind
        self.isScheduleDue = isScheduleDue
    }
}

/// The kind of upcoming work named by a ``MigrationAdvance/next`` outlook — a verbatim marshal of
/// the upstream engine's `state::StepKind` (the outlook's kind ALONE: WHICH transaction a wake-up
/// serves is decided by the `migrationAdvanceStep` call that serves it, not by this value).
///
/// ``prove``, ``broadcast``, ``rebuild`` and ``replan`` are the only outlooks the engine
/// constructs today (upstream's own outlook derivation maps every other case to no outlook); the
/// SDK still mirrors the full upstream enum — ``reevaluate``, ``waiting``, ``complete`` included —
/// so this marshal never invents a projection of its own.
public enum MigrationStepKind: Equatable, Sendable {
    case prove
    case broadcast
    case rebuild
    case replan
    case reevaluate
    case waiting
    case complete
}

/// The engine's OUTLOOK (upstream #2936, `Advance::next`): what session to plan for next,
/// assuming the step it rode in on (``MigrationAdvance/step``) is executed and recorded.
public struct MigrationNextWork: Equatable, Sendable {
    /// The earliest height at which the outlook's work becomes serviceable — upstream's `tip + 1`
    /// target convention, directly comparable with a caller's own scanned/estimated targets. A
    /// FLOOR, not an appointment: dependencies still have to mine, and the wake-up's own
    /// `migrationAdvanceStep` call re-verifies (and may displace) it — this value holds only as of
    /// the call that returned it, and the NEXT call's outlook supersedes it.
    public let height: BlockHeight
    /// What session to plan for the upcoming work: a ``MigrationStepKind/broadcast`` outlook needs
    /// no sync, a ``MigrationStepKind/prove`` one is sync-bound (the ZIP 318 session separation
    /// `migrationAdvanceStep`'s own doc describes), and ``MigrationStepKind/replan``/
    /// ``MigrationStepKind/rebuild`` need user or spend-authority action.
    /// ``MigrationStepKind/reevaluate``/``MigrationStepKind/waiting``/``MigrationStepKind/complete``
    /// are not constructible outlooks upstream (see ``MigrationStepKind``'s doc) but are mirrored
    /// so the marshal never projects one case onto another.
    public let kind: MigrationStepKind

    /// Creates a `MigrationNextWork`.
    public init(height: BlockHeight, kind: MigrationStepKind) {
        self.height = height
        self.kind = kind
    }
}

/// The engine's answer to `Synchronizer.migrationAdvanceStep(accountUUID:)` /
/// `ZcashRustBackendWelding.migrationAdvanceStep(for:)`: the step to perform NOW
/// (``MigrationAdvanceStep``, unchanged) plus the advisory OUTLOOK (upstream #2936) — what the
/// migration will next need, assuming this step is executed. `next == nil` means nothing is
/// height-schedulable: what follows is chain-driven (an in-flight transaction mining), user-driven
/// (a signature, a replan), or the migration is terminal — see ``MigrationNextWork`` for the full
/// contract.
public struct MigrationAdvance: Equatable, Sendable {
    /// The step to perform now — see ``MigrationAdvanceStep`` for the full discharge contract.
    public let step: MigrationAdvanceStep
    /// The advisory outlook: what session to plan for next, or `nil` when nothing is
    /// height-schedulable.
    public let next: MigrationNextWork?

    /// Creates a `MigrationAdvance`.
    public init(step: MigrationAdvanceStep, next: MigrationNextWork?) {
        self.step = step
        self.next = next
    }
}

/// One sync/proving wake-up of the stored run's schedule, as returned by
/// `Synchronizer.migrationSyncWakeups(accountUUID:)`: the block height at which the wallet should
/// wake, sync, and prove, plus the ids of the transfers that wake-up is responsible for proving.
///
/// A verbatim marshal of the upstream engine's `SyncWakeup`. Wake-up heights are floored at the
/// scanned tip (a row at exactly the tip means "right now"), and jitter is re-drawn on every call
/// — two calls may legitimately differ, so recompute (and re-register with the OS) after any
/// state change rather than caching a schedule.
public struct MigrationSyncWakeup: Equatable, Sendable {
    /// The block height at which to wake, sync, and prove.
    public let height: BlockHeight
    /// The ids of the transfers this wake-up is responsible for proving.
    public let coversTransferIds: [UInt32]

    /// Creates a `MigrationSyncWakeup`.
    public init(height: BlockHeight, coversTransferIds: [UInt32]) {
        self.height = height
        self.coversTransferIds = coversTransferIds
    }
}

/// One scanned block's `(height, header time)` sample from the wallet database, as returned by
/// `ZcashRustBackendWelding.migrationBlockRateSamples(window:)` — the raw input of
/// ``ChainTipEstimator``'s measured-block-rate chain-tip projection. Internal: apps consume the
/// projection (`Synchronizer.estimatedMigrationChainTip()`), never the samples.
struct MigrationBlockRateSample: Equatable, Sendable {
    /// The scanned block's height.
    let height: BlockHeight
    /// The block header's time, as Unix epoch seconds.
    let unixTime: Int64
}

/// A single note-preparation transaction in a schedule preview — an element of
/// ``MigrationSchedule/preparations``: the transfer rows alone do not surface the preparations
/// that mint their funding notes.
///
/// Populated either from a fresh plan at propose time (numbered and scheduled exactly as the
/// engine's commit path will persist them once confirmed) or, once a run is stored, read straight
/// off its persisted rows.
public struct MigrationPreparationStep: Identifiable, Equatable, Sendable, Codable {
    /// This transaction's stable engine-issued id (the same ordinal space as
    /// ``MigrationTransferProposal/id`` and ``MigrationTransactionStatus/id``).
    public let id: UInt32
    /// The dependency-layer index this preparation belongs to.
    public let layer: Int
    /// This preparation's index within `layer`.
    public let index: Int
    /// The height at or after which this preparation is due to broadcast.
    public let broadcastHeight: BlockHeight
    /// The ids of the transactions that must mine before this one may broadcast: the WHOLE
    /// preceding layer's ids (empty for layer 0) — the engine does not narrow this to the
    /// specific producer(s) a layer's inputs spend.
    public let dependsOn: [UInt32]

    /// Creates a `MigrationPreparationStep`.
    public init(id: UInt32, layer: Int, index: Int, broadcastHeight: BlockHeight, dependsOn: [UInt32]) {
        self.id = id
        self.layer = layer
        self.index = index
        self.broadcastHeight = broadcastHeight
        self.dependsOn = dependsOn
    }
}

/// The signing-round action budgets of the external signers the SDK knows about, mirroring the
/// upstream engine's `SigningRoundBudget`: how many Orchard-family actions one signing session
/// may carry (a preparation transaction weighs 16 actions, a transfer 3).
///
/// Feed one of these (or a device-specific value) to
/// `Synchronizer.batchMigrationPcztsForSigning(_:maxActionsPerSession:)` to split an ordered PCZT
/// batch into device-sized sessions, and compare with
/// ``MigrationRunEstimate/totalKeystoneSigningSessions`` — which is precomputed under the
/// ``keystone`` budget by the upstream optimal packing.
public enum MigrationSigningBudget {
    /// A Keystone-class hardware signer's per-round budget: 96 actions
    /// (`SigningRoundBudget::KEYSTONE` upstream).
    public static let keystone = 96
    /// The default budget for signers without a device-specific limit: 512 actions
    /// (`SigningRoundBudget::DEFAULT` upstream).
    public static let `default` = 512
}

/// A snapshot of an in-progress migration, as returned by
/// `ZcashRustBackendWelding.migrationProgress(for:)`.
///
/// Present only while there is something live to report: an engine-tracked run that is ACTIVE
/// (not terminal), or a recorded immediate sweep that is still unmined and unexpired. A terminal
/// run — complete or cancelled — reports `nil`, as does an immediate sweep once it mines
/// (consumed) or expires (the offer re-arms).
public struct MigrationProgress: Equatable, Sendable {
    /// The number of scheduled transfers confirmed on-chain so far.
    public let completedTransfers: Int
    /// The total number of transfers in the current schedule.
    public let totalTransfers: Int
    /// The Orchard-pool value not yet migrated to Ironwood: the account's live spendable Orchard
    /// balance (what is still in the old pool), not a run-internal remainder.
    public let remainingOrchard: Zatoshi
    /// The height at which the next transfer becomes broadcastable, or `nil` if none is scheduled.
    public let nextTransferReadyAtHeight: BlockHeight?
    /// Whether this snapshot belongs to the immediate (single-transaction) send-max migration lane
    /// rather than an engine-tracked schedule. The app uses it to keep the immediate aftermath
    /// quiet (no per-transfer progress UI). Engine-tracked runs report `false`.
    public let isImmediate: Bool

    /// Creates a `MigrationProgress`.
    public init(
        completedTransfers: Int,
        totalTransfers: Int,
        remainingOrchard: Zatoshi,
        nextTransferReadyAtHeight: BlockHeight?,
        isImmediate: Bool = false
    ) {
        self.completedTransfers = completedTransfers
        self.totalTransfers = totalTransfers
        self.remainingOrchard = remainingOrchard
        self.nextTransferReadyAtHeight = nextTransferReadyAtHeight
        self.isImmediate = isImmediate
    }
}

/// Compatibility reasons for ``MigrationTransactionStatus/State/invalid(reason:)``. Upstream now
/// stores unsatisfiability orthogonally to lifecycle state and records node rejection as testimony;
/// the wrapper projects those details into this existing public enum.
public enum MigrationInvalidReason: Equatable, Sendable {
    /// An input was spent, or the transaction inherited unsatisfiability from a dependency.
    case fundingSpent
    /// Another unsatisfiable cause, or a node rejection awaiting reevaluation against scanned data.
    case rejectedInvalid
    /// Retained for source compatibility. New expiry determinations surface as ``Blocker/expired``.
    case rejectedExpired
}

/// One migration transaction's LIVE status, as the engine computes it — an element of the array
/// returned by `ZcashRustBackendWelding.migrationTransactionStatuses(for:)` /
/// `Synchronizer.migrationTransactionStatuses(accountUUID:)`. A verbatim marshal of the engine's
/// own `MigrationState::transaction_statuses`: nothing here is derived independently of the
/// engine's view, and it is reconciled against mined transactions at every read (the same
/// read-path convention as `migrationAdvanceStep`), so a transaction the wallet's own scan has
/// since observed mined is reported `.mined` here even if the stored run still marks it broadcast.
public struct MigrationTransactionStatus: Equatable, Sendable {
    /// This transaction's kind: a note-PREPARATION at a given dependency-layer/index, or a
    /// phase-2 pool-crossing TRANSFER at a given funding-note crossing index.
    public enum Kind: Equatable, Sendable {
        /// A note-preparation transaction: `layer` is its dependency-layer index, `index` its
        /// position within that layer.
        case preparation(layer: Int, index: Int)
        /// A pool-crossing transfer: `crossing` is its funding-note crossing index.
        case transfer(crossing: Int)
    }

    /// This transaction's lifecycle state. `broadcast`/`mined`/`invalid` fold the engine's
    /// `txid`/`mined_height`/`invalid_reason` payloads into the matching case, so illegal
    /// combinations (a mined row still carrying a broadcast txid, a broadcast row with none, or
    /// an invalid row without its reason) are unrepresentable.
    ///
    /// - Note: This public model continues to expose only the mined height for `.mined`, even
    ///   though the upstream lifecycle now retains the txid too. Use transaction history when the
    ///   mined txid is needed.
    public enum State: Equatable, Sendable {
        /// Built but not yet signed.
        case awaitingSignature
        /// Signed but not yet proven.
        case signed
        /// Proven and ready to broadcast.
        case proved
        /// Broadcast to the network as `txid` (the SDK's raw/internal byte order), not yet
        /// observed mined.
        case broadcast(txid: Data)
        /// Mined at `height`.
        case mined(height: BlockHeight)
        /// Dead according to the engine's satisfiability oracle after a funding input became
        /// unavailable or the network rejected the broadcast. `reason` is the compatibility
        /// projection of that upstream condition. Chain inclusion OUTRANKS it: a
        /// row the wallet's scan has observed mined reports `.mined`, never `.invalid` — a stale
        /// verdict cannot shadow a landed transaction. Resolved out-of-band via the
        /// ``MigrationAdvanceStep/replan`` discharge mapping (typically
        /// `restartCurrentMigrationStep`).
        case invalid(reason: MigrationInvalidReason)
    }

    /// The action available now, when `isReady` is `true`.
    public enum NextAction: Equatable, Sendable {
        /// Signed and ready to be proven.
        case prove
        /// Proven and ready to be broadcast.
        case broadcast
    }

    /// Why this transaction is not yet actionable, when it is waiting (and not already broadcast
    /// or mined).
    public enum Blocker: Equatable, Sendable {
        /// Waiting on another transaction of the same run it depends on.
        case dependencies
        /// Waiting for its scheduled height.
        case schedule
        /// Waiting for a boundary anchor it can prove against.
        case anchorBoundary
        /// Waiting for its signature.
        case signature
        /// Its expiry height has elapsed.
        case expired
        /// Marked dead by an observed event (its state is
        /// ``MigrationTransactionStatus/State/invalid(reason:)``): no chain condition makes it
        /// actionable again — resolution is out-of-band, via the
        /// ``MigrationAdvanceStep/replan`` discharge mapping.
        case invalid
    }

    /// This transaction's stable id (the engine's own raw ordinal). Stable across reads and
    /// across a stale-transfer rebuild (a rebuilt transfer keeps its id; only its state and
    /// heights change), so a wallet may use it as a durable row key. It is the same ordinal the
    /// schedule surfaces carry as their opaque string id — `String(status.id)` equals
    /// ``MigrationTransferProposal/id`` / ``PreparedMigrationTransfer/id`` for the same
    /// transaction — so status rows (which carry no amount) join to their schedule row by id.
    public let id: UInt32
    /// This transaction's kind and per-kind payload.
    public let kind: Kind
    /// This transaction's lifecycle state.
    public let state: State
    /// The height at or after which this transaction is due to broadcast.
    public let scheduledHeight: BlockHeight
    /// The height after which this transaction can no longer be mined (ZIP 203); `nil` when it
    /// never expires (the engine's own `0` sentinel).
    public let expiryHeight: BlockHeight?
    /// Whether the wallet can act on this transaction right now.
    public let isReady: Bool
    /// The action available now, when `isReady` is `true`; `nil` otherwise.
    public let nextAction: NextAction?
    /// Why this transaction is not yet actionable, when waiting (and not already broadcast or
    /// mined); `nil` otherwise.
    public let blockedOn: Blocker?
    /// The ids of the transactions of the same run that must mine before this one can be built or
    /// broadcast (the engine's own `TransactionStatus::depends_on`); empty when it depends on
    /// nothing.
    public let dependsOn: [UInt32]
    /// The bucketed boundary height this transaction's anchor was drawn against, or `nil` when
    /// none was drawn. Only ever set for a TRANSFER: a preparation is exempt from anchor
    /// bucketing by design — it proves against a near-tip witnessable anchor at proving time
    /// instead of a drawn boundary — so this is always `nil` for a
    /// ``Kind/preparation(layer:index:)`` row.
    public let anchorBoundaryHeight: BlockHeight?

    /// Creates a `MigrationTransactionStatus`.
    public init(
        id: UInt32,
        kind: Kind,
        state: State,
        scheduledHeight: BlockHeight,
        expiryHeight: BlockHeight?,
        isReady: Bool,
        nextAction: NextAction?,
        blockedOn: Blocker?,
        dependsOn: [UInt32],
        anchorBoundaryHeight: BlockHeight?
    ) {
        self.id = id
        self.kind = kind
        self.state = state
        self.scheduledHeight = scheduledHeight
        self.expiryHeight = expiryHeight
        self.isReady = isReady
        self.nextAction = nextAction
        self.blockedOn = blockedOn
        self.dependsOn = dependsOn
        self.anchorBoundaryHeight = anchorBoundaryHeight
    }
}

extension Array where Element == MigrationTransactionStatus {
    /// Whether the run's preparation (note-split) phase is fully mined: `true` iff every
    /// ``MigrationTransactionStatus/Kind/preparation(layer:index:)``-kind row is `.mined` —
    /// vacuously `true` when the run needs no preparations at all.
    ///
    /// The replacement for the removed `MigrationState.splitPendingConfirmation`: a host that
    /// rendered "preparing your funds" off that state derives the same signal from this
    /// predicate over `migrationTransactionStatuses(accountUUID:)`.
    public var isPreparationPhaseComplete: Bool {
        allSatisfy { status in
            guard case .preparation = status.kind else {
                return true
            }
            if case .mined = status.state {
                return true
            }
            return false
        }
    }
}

/// The optimal note split proposed for the spendable Orchard balance, as returned by
/// `ZcashRustBackendWelding.migrationPrepareNoteSplit(for:)`.
public struct NoteSplitProposal: Equatable, Sendable {
    /// The per-note output values of the proposed split transaction.
    public let outputNotes: [Zatoshi]
    /// The fee paid by the split transaction itself.
    public let fee: Zatoshi
    /// Opaque identifier of the SDK-native cached migration plan this proposal was rendered
    /// from. The plan's details never leave the native side: commit calls pass the handle back,
    /// and the native side refuses to sign any plan other than the one it identifies — throwing
    /// `migrationPlanStale` when a later propose/prepare call superseded it, so what gets signed
    /// is always exactly what the user reviewed. `0` means no plan was cached (the empty
    /// nothing-to-migrate proposal).
    public let proposalHandle: UInt64

    /// Creates a `NoteSplitProposal`.
    public init(outputNotes: [Zatoshi], fee: Zatoshi, proposalHandle: UInt64) {
        self.outputNotes = outputNotes
        self.fee = fee
        self.proposalHandle = proposalHandle
    }
}

/// A single scheduled Orchard -> Ironwood transfer, as one element of a `MigrationSchedule`.
public struct MigrationTransferProposal: Identifiable, Equatable, Sendable, Codable {
    /// The transfer's engine-issued id.
    public let id: UInt32
    /// The value that crosses the turnstile: what this transfer adds to the destination pool, and
    /// one of the round `{1,2,5}×10ⁿ` denominations the run was planned in. The note the transfer
    /// spends is larger — it also carries the buffer that pays the transfer's own fee — but that
    /// is a spend-side detail the user is not asked to approve.
    public let amount: Zatoshi
    /// The "now" reference height at proposal time (the chain tip). With ZIP 374 the real anchor
    /// is drawn per transfer and installed at proving time, so this field is NOT a commitment-tree
    /// anchor; it exists so duration math can measure waits from the proposal's own "now", and for
    /// `Codable` compatibility with previously persisted schedules.
    public let anchorHeight: BlockHeight
    /// The height after which the platform may broadcast this transfer.
    public let nextExecutableAfterHeight: BlockHeight
    /// The height after which this transfer is no longer valid.
    public let expiryHeight: BlockHeight

    /// Creates a `MigrationTransferProposal`.
    public init(
        id: UInt32,
        amount: Zatoshi,
        anchorHeight: BlockHeight,
        nextExecutableAfterHeight: BlockHeight,
        expiryHeight: BlockHeight
    ) {
        self.id = id
        self.amount = amount
        self.anchorHeight = anchorHeight
        self.nextExecutableAfterHeight = nextExecutableAfterHeight
        self.expiryHeight = expiryHeight
    }
}

/// A full migration schedule presented to the user for one-time confirmation, as returned by
/// `ZcashRustBackendWelding.migrationProposeTransfers(for:)` and related calls.
///
/// `Codable` so the platform can cache the confirmed schedule (e.g. while awaiting an external
/// signer) without re-deriving it from the engine.
public struct MigrationSchedule: Equatable, Sendable, Codable {
    /// The scheduled transfers, in execution order.
    public let transfers: [MigrationTransferProposal]
    /// A rough estimate of how long the schedule takes to fully execute, in hours — measured
    /// from the proposal's (or re-serve's) own "now" to the last scheduled transfer, so a
    /// re-served schedule's value naturally shrinks as time passes.
    public let estimatedDurationHours: Int
    /// Opaque identifier of the SDK-native cached plan this schedule was rendered from — see
    /// `NoteSplitProposal.proposalHandle` for the contract. The transfer fields above are for
    /// display; commit calls pass only this handle back, so the native side signs exactly the
    /// identified plan. `0` means no cached plan backs this schedule (the empty
    /// nothing-to-migrate answer, or a schedule read from the already-committed stored run —
    /// which commit calls resume without consulting a handle). A schedule decoded from a
    /// PERSISTED copy also carries `0`: the native cache is process-lifetime, so a persisted
    /// schedule can never identify a live plan — re-propose instead of committing it.
    public let proposalHandle: UInt64
    /// The note-preparation transactions of the same plan, in broadcast order — the transfer rows
    /// alone do not surface the preparations that mint their funding notes. Plan data at propose
    /// time; the stored run's persisted rows on re-serve.
    public let preparations: [MigrationPreparationStep]

    /// The persisted-envelope keys. Explicit (the compiler stops synthesizing `CodingKeys` once
    /// BOTH `init(from:)` and `encode(to:)` are hand-written), with the raw names the synthesized
    /// conformance used — existing persisted copies keep decoding unchanged.
    private enum CodingKeys: String, CodingKey {
        case transfers
        case estimatedDurationHours
        case proposalHandle
        case preparations
    }

    /// Creates a `MigrationSchedule`.
    public init(
        transfers: [MigrationTransferProposal],
        estimatedDurationHours: Int,
        proposalHandle: UInt64,
        preparations: [MigrationPreparationStep]
    ) {
        self.transfers = transfers
        self.estimatedDurationHours = estimatedDurationHours
        self.proposalHandle = proposalHandle
        self.preparations = preparations
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.transfers = try container.decode([MigrationTransferProposal].self, forKey: .transfers)
        self.estimatedDurationHours = try container.decode(Int.self, forKey: .estimatedDurationHours)
        // Absent in copies persisted before the handle existed — and a persisted handle could
        // not identify a live plan anyway (the native cache is process-lifetime), so `0` ("no
        // plan") is the honest decode either way. `encode(to:)` below never writes the key, so
        // this branch is also what every round-tripped copy takes.
        self.proposalHandle = try container.decodeIfPresent(UInt64.self, forKey: .proposalHandle) ?? 0
        // Absent in copies persisted before the preparations rows existed; an empty list is the
        // honest decode (the persisted copy simply never carried them).
        self.preparations = try container.decodeIfPresent([MigrationPreparationStep].self, forKey: .preparations) ?? []
    }

    /// Encodes everything EXCEPT `proposalHandle`: the handle identifies a PROCESS-LIFETIME native
    /// plan cache entry, so a persisted copy could never identify a live plan — persisting the raw
    /// number would only invite a later launch to present it as meaningful. Omitting it makes the
    /// documented decode contract (`init(from:)` above reads an absent handle as `0`, "no plan")
    /// true of every persisted copy by construction, not just of pre-handle legacy files.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(transfers, forKey: .transfers)
        try container.encode(estimatedDurationHours, forKey: .estimatedDurationHours)
        try container.encode(preparations, forKey: .preparations)
    }
}

/// An estimate of migrating the account's whole spendable Orchard balance across successive
/// migration RUNS ("rounds"), as returned by
/// `ZcashRustBackendWelding.estimateMigrationRuns(accountUUID:)`.
///
/// A balance beyond one run's capacity migrates over several runs; each run carries BOTH what it
/// migrates (the note-split crossings) and what preparing it costs (the note-preparation layers
/// and transactions), so the two can be compared before anything is planned or committed.
///
/// A run's capacity is PER ACCOUNT, decided by how the account signs: an account created or
/// imported with `keySource == "keystone"` (compared case-insensitively) is sized to what a
/// Keystone signs in ONE QR-scanned round — the 96-action ``MigrationSigningBudget/keystone``
/// budget — so its runs are smaller and more numerous, and each ``Run/keystoneSigningSessions`` is
/// 1 unless even a one-note run overflows the round; every other account is signed in process, has
/// no per-round cost to bound, and is sized by a 200-note cap — fewer, larger runs. The same
/// sizing drives `proposeMigrationTransfers`, so this estimate always describes the runs that get
/// planned.
///
/// External-signer workload is expressed in ACTIONS, not transaction counts: a preparation
/// transaction weighs 16 Orchard-family actions and a transfer 3, so per-run ``Run/actions`` is
/// the signing workload and ``Run/keystoneSigningSessions`` the number of signer interactions a
/// Keystone-class device (the 96-action ``MigrationSigningBudget/keystone`` budget) needs, as
/// computed by the upstream optimal `MinRounds` packing. A count-based
/// `ceil(transactions / maxTransactionsPerSession)` UNDERCOUNTS that: 6 preparations plus 1
/// transfer is 99 actions — one Keystone round over the 96-action budget — so it needs 2 rounds,
/// while any count-based ceiling admitting ≥ 7 transactions per session claimed 1. For splitting
/// an actual PCZT batch (any budget, order preserved), use
/// `Synchronizer.batchMigrationPcztsForSigning(_:maxActionsPerSession:)`.
public struct MigrationRunEstimate: Equatable, Sendable {
    /// A per-run entry: what one migration run migrates (the note-split side) and what preparing
    /// it costs (the note-preparation side), so the two can be compared.
    public struct Run: Equatable, Sendable {
        /// The total value that crosses the turnstile in this run (the sum of its crossing
        /// denominations).
        public let migratable: Zatoshi
        /// The number of pool-crossing transfers this run makes: one per self-funding note the
        /// note split produced for it.
        public let crossings: Int
        /// The number of sequential note-preparation layers this run needs — its wall-clock
        /// depth, since each layer waits for the previous one to mine before it can broadcast.
        public let preparationLayers: Int
        /// The number of note-preparation transactions this run builds across all its layers.
        public let preparationTransactions: Int
        /// The total Orchard-family actions a signer processes for this run: 16 per preparation
        /// transaction, 3 per transfer. The signing WORKLOAD — a proxy for signing time —
        /// distinct from ``keystoneSigningSessions``, which counts signer INTERACTIONS.
        public let actions: Int
        /// The number of signing rounds this run needs from a Keystone-class external signer
        /// (``MigrationSigningBudget/keystone``, 96 actions per round), computed by the upstream
        /// optimal `MinRounds` packing — see the type doc for why a count-based ceiling
        /// undercounts this. For a `keySource == "keystone"` account the run is sized to fit one
        /// round, so this is 1 (more only when even a one-note run overflows); for an in-process
        /// account it is what a Keystone would need for a run of this shape — a comparison figure.
        public let keystoneSigningSessions: Int

        /// Creates a `Run`.
        public init(
            migratable: Zatoshi,
            crossings: Int,
            preparationLayers: Int,
            preparationTransactions: Int,
            actions: Int,
            keystoneSigningSessions: Int
        ) {
            self.migratable = migratable
            self.crossings = crossings
            self.preparationLayers = preparationLayers
            self.preparationTransactions = preparationTransactions
            self.actions = actions
            self.keystoneSigningSessions = keystoneSigningSessions
        }

        /// The total number of transactions this run builds and signs: its preparation
        /// transactions plus one pool-crossing transfer per funding note.
        public var transactions: Int {
            preparationTransactions + crossings
        }
    }

    /// The per-run estimates, in run order. Empty when nothing migrates (a zero or fully
    /// sub-quantum balance) — a legitimate estimate, not an error.
    public let runs: [Run]
    /// The value left in Orchard after the last run — below the smallest self-funding note, so it
    /// never migrates. `.zero` when the balance divides exactly into self-funding notes and fees.
    public let finalResidual: Zatoshi

    /// Creates a `MigrationRunEstimate`.
    public init(runs: [Run], finalResidual: Zatoshi) {
        self.runs = runs
        self.finalResidual = finalResidual
    }

    /// The expected number of migration runs ("rounds") to migrate the whole balance: zero when
    /// the balance is below the smallest self-funding note, so nothing migrates.
    public var runCount: Int {
        runs.count
    }

    /// The total value that migrates across all runs (the sum of each run's `migratable`).
    public var totalMigratable: Zatoshi {
        runs.reduce(Zatoshi.zero) { $0 + $1.migratable }
    }

    /// The total number of pool-crossing transfers across all runs.
    public var totalCrossings: Int {
        runs.reduce(0) { $0 + $1.crossings }
    }

    /// The total number of note-preparation layers across all runs.
    public var totalPreparationLayers: Int {
        runs.reduce(0) { $0 + $1.preparationLayers }
    }

    /// The total number of note-preparation transactions across all runs.
    public var totalPreparationTransactions: Int {
        runs.reduce(0) { $0 + $1.preparationTransactions }
    }

    /// The total number of transactions the whole migration builds and signs across all runs
    /// (equivalently `totalPreparationTransactions` plus `totalCrossings`).
    public var totalTransactions: Int {
        runs.reduce(0) { $0 + $1.transactions }
    }

    /// The total signing workload across all runs, in Orchard-family actions (the sum of each
    /// run's ``Run/actions``).
    public var totalActions: Int {
        runs.reduce(0) { $0 + $1.actions }
    }

    /// The total number of Keystone signing rounds the whole migration needs (the sum of each
    /// run's ``Run/keystoneSigningSessions``) — the number of times the user must interact with a
    /// Keystone-class hardware signer.
    ///
    /// A SUM, never a re-packing across runs: a later run's transactions spend notes an earlier
    /// run must mine first, so each run is signed on its own and any spare capacity in a run's
    /// last round goes unused.
    public var totalKeystoneSigningSessions: Int {
        runs.reduce(0) { $0 + $1.keystoneSigningSessions }
    }
}

/// The proposal for the immediate (single-transaction) Orchard -> Ironwood migration, as returned
/// by `Synchronizer.proposeImmediateMigration(accountUUID:)`: an ordinary send-max transaction that
/// sweeps the account's whole spendable Orchard balance to its own address. Unlike
/// `MigrationSchedule`, this is held entirely by the caller -- there is no engine plan cache behind
/// it, so nothing about it can go stale beyond the proposal's own validity window.
public struct ImmediateMigrationProposal: Equatable {
    /// The underlying proposal: feed to `Synchronizer.createProposedTransactions(proposal:spendingKey:)`
    /// (software accounts) or `Synchronizer.createPCZTFromProposal(accountUUID:proposal:)` (Keystone
    /// accounts) exactly like any other ordinary transfer.
    public let proposal: Proposal
    /// The net swept amount -- what arrives in the Ironwood pool once mined. The proposal's single
    /// payment value: the account's spendable Orchard notes, minus `fee`.
    public let amount: Zatoshi
    /// The fee this proposal pays, per `Proposal.totalFeeRequired()`.
    public let fee: Zatoshi

    /// Creates an `ImmediateMigrationProposal`.
    public init(proposal: Proposal, amount: Zatoshi, fee: Zatoshi) {
        self.proposal = proposal
        self.amount = amount
        self.fee = fee
    }
}

/// A migration transaction handed to the platform.
///
/// WHAT ``pczt`` CARRIES depends on the producer: the delivery executor
/// (`migrationTakeBroadcastTransaction(id:for:)`) and the note-split ceremony
/// (`migrationSignNoteSplit`) both serve through the store's atomic broadcast seam, so theirs is
/// the FINALIZED CONSENSUS TRANSACTION — submittable as-is. The storage receipt
/// `migrationStoreSignedNoteSplitPczts` returns is a serialized PCZT, not submittable until the
/// engine has proved it and a later `migrationTakeBroadcastTransaction(id:for:)` serves the
/// broadcastable, proven value once a crank names it.
public struct PreparedMigrationTransfer: Equatable, Sendable {
    /// The transfer's engine-issued id.
    public let id: UInt32
    /// The finalized transaction's id, in the SDK's raw/internal byte order (matching `TxId.id`,
    /// not the reversed display-hex order produced by `Data.toHexStringTxId()`). Zeroed when the
    /// value is a STORAGE RECEIPT (`migrationStoreSignedNoteSplitPczts`) whose transaction has not
    /// been proven yet — the broadcastable value is served by the delivery lane.
    public let txid: Data
    /// The artifact: a finalized consensus transaction or a serialized PCZT per the producer, as
    /// the type doc above spells out. The property keeps its historical name.
    public let pczt: Data

    /// Creates a `PreparedMigrationTransfer`.
    public init(id: UInt32, txid: Data, pczt: Data) {
        self.id = id
        self.txid = txid
        self.pczt = pczt
    }
}

/// What one prove pass accomplished: how many transactions it proved, and the txids of the
/// PREPARATIONS among them.
///
/// THE TXIDS ARE THE HANDOFF, and they name preparations only. A proved preparation is a complete
/// PCZT (signatures and proofs); it is ZIP 318-exempt, and the engine's own contract is that a
/// preparation is broadcast as soon as it is proved — so its submission is the host's ORDINARY
/// path: take each txid to `takeMigrationPreparation(accountUUID:byTxid:)`, submit the bytes it
/// hands back through whatever machinery the host already uses for raw transactions, and record
/// the outcome through the standard record path. A transfer crosses the turnstile on the drive's
/// own schedule and is delivered by a `MigrationAdvanceStep/broadcast(_:)` instruction alone, so
/// its txid never appears here: appearing here MEANS retrievable.
///
/// ``totalProved`` counts both kinds, so it is the honest measure of a pass's progress —
/// `0` with no txids is the ordinary "nothing in this batch is provable right now" answer.
public struct MigrationProveOutcome: Equatable, Sendable {
    /// How many transactions this pass proved — preparations AND transfers.
    public let totalProved: Int
    /// The proved preparations' txids, in the order they were proved, in the SDK's raw/internal
    /// byte order (matching ``PreparedMigrationTransfer/txid``, not the reversed display-hex order
    /// produced by `Data.toHexStringTxId()`). Empty when the pass proved no preparation.
    public let preparationTxids: [Data]

    /// Creates a `MigrationProveOutcome`.
    public init(totalProved: Int, preparationTxids: [Data]) {
        self.totalProved = totalProved
        self.preparationTxids = preparationTxids
    }
}

/// The platform's outcome of broadcasting (or attempting to broadcast) a prepared migration
/// transfer, reported back to the migration engine via
/// `ZcashRustBackendWelding.migrationRecordTransferResult(transferId:result:for:)`.
public enum MigrationTransferResult: Equatable, Sendable {
    /// The transfer was accepted by the network as `txId`.
    ///
    /// `txId` is the display-form hex-encoded transaction id: the same byte order produced by
    /// `Data.toHexStringTxId()` and consumed by `TxId.init(_ id: String)` (reversed relative to
    /// the transaction's raw/internal byte order), matching how the SDK renders txids elsewhere.
    case success(txId: String)
    /// The broadcast failed for a network-level reason; `retryable` indicates whether the
    /// platform should retry the same prepared transfer later.
    case networkError(retryable: Bool)
    /// The transfer's input note was no longer valid (e.g. already spent) at broadcast time.
    case invalidNote
    /// The transfer's anchor/expiry elapsed before it could be broadcast.
    case expired
}

/// An unsigned-but-proven PCZT for one scheduled transfer, awaiting an external signer (see
/// `ZcashRustBackendWelding.migrationCreateUnsignedTransferPczts(for:for:)`).
public struct MigrationUnsignedTransferPczt: Equatable, Sendable {
    /// The transfer's engine-issued id.
    ///
    /// The two signed-PCZT STORE calls (`storeSignedNoteSplitPCZTs` /
    /// `storeSignedMigrationSchedulePCZTs`) look the transaction up by it, so it must be the id
    /// the engine issued. The Keystone batch-signing bridge, by contrast, never looks it up:
    /// `applyKeystoneBatchSignatures` echoes each id back onto the returned signed pair
    /// positionally, so on that path the id is a pure correlation label. Callers that need to
    /// tell a preparation PCZT from a schedule transfer keep that mapping themselves — the batch
    /// is positional, and engine ids number every preparation transaction before the transfers.
    public let id: UInt32
    /// The serialized, proven-but-unsigned PCZT.
    public let pczt: Data
    /// The signer action weight of this transaction for budget batching: 16 for a preparation,
    /// 3 for a transfer — feed an ordered batch of these rows to
    /// `Synchronizer.batchMigrationPcztsForSigning(_:maxActionsPerSession:)` to split it into
    /// device-sized signing sessions before dispatching.
    ///
    /// `0` on values reconstructed by `applyKeystoneBatchSignatures(pczts:batchSignResponse:)`'s
    /// signed counterparts: that path rebuilds PCZTs from caller-held bytes without engine
    /// context, so it has no stored kind to weigh — batching happens BEFORE signing, over these
    /// CREATE/RE-SERVE rows, never over its result.
    public let actions: Int

    /// Creates a `MigrationUnsignedTransferPczt`.
    public init(id: UInt32, pczt: Data, actions: Int) {
        self.id = id
        self.pczt = pczt
        self.actions = actions
    }
}

/// An externally signed PCZT for one scheduled transfer, to be handed back to the engine via
/// `ZcashRustBackendWelding.migrationStoreSignedSchedulePczts(_:for:)`.
public struct MigrationSignedTransferPczt: Equatable, Sendable {
    /// The transfer's engine-issued id (must match the corresponding
    /// `MigrationUnsignedTransferPczt.id` — the STORE calls consuming this type look the
    /// transaction up by it, while `applyKeystoneBatchSignatures` produces these pairs with
    /// whatever ids it was given, echoed back positionally).
    public let id: UInt32
    /// The serialized, signed PCZT.
    public let pczt: Data

    /// Creates a `MigrationSignedTransferPczt`. Apps construct this directly after routing the
    /// corresponding `MigrationUnsignedTransferPczt` through an external signer.
    public init(id: UInt32, pczt: Data) {
        self.id = id
        self.pczt = pczt
    }
}

/// A signing device's firmware version, as reported in a Keystone batch-signing response envelope
/// (see `KeystoneBatchDecodeResult.firmwareVersion`).
///
/// `Comparable` lexicographically (major, then minor, then build) so a host can gate a feature on
/// a minimum device firmware version.
public struct KeystoneFirmwareVersion: Equatable, Sendable, Comparable {
    public let major: UInt8
    public let minor: UInt8
    public let build: UInt8

    /// Creates a `KeystoneFirmwareVersion`.
    public init(major: UInt8, minor: UInt8, build: UInt8) {
        self.major = major
        self.minor = minor
        self.build = build
    }

    public static func < (lhs: KeystoneFirmwareVersion, rhs: KeystoneFirmwareVersion) -> Bool {
        if lhs.major != rhs.major {
            return lhs.major < rhs.major
        }
        if lhs.minor != rhs.minor {
            return lhs.minor < rhs.minor
        }
        return lhs.build < rhs.build
    }
}

/// The result of feeding one scanned QR frame to
/// `Synchronizer.decodeKeystoneSignBatchPart(_:expectedRequestId:)`.
///
/// `complete == false` means more frames are needed: `progress` is the 0-100 completion
/// percentage so far, and `data`/`firmwareVersion` are `nil`. `complete == true` means `data`
/// holds the serialized batch-signature response to pass to
/// `Synchronizer.applyKeystoneBatchSignatures(pczts:batchSignResponse:)` -- the response is
/// signatures-only, no PCZT is echoed back by the device.
///
/// - Note: `firmwareVersion` comes from the response envelope itself (the signing device's own
///   reported firmware version), not from any field recovered from a signed PCZT. It is set only
///   once `complete`, and only when the envelope carried it; it is the ONLY way to learn the
///   signing device's firmware version in the batch flow -- `applyKeystoneBatchSignatures`
///   reconstructs each "signed" PCZT from the caller's own retained unsigned bytes plus the
///   response's signatures, never from device-returned PCZT bytes, so there is no PCZT-embedded
///   firmware stamp to fall back on here (unlike the single-transaction Keystone sign flow).
public struct KeystoneBatchDecodeResult: Equatable, Sendable {
    /// Whether the full multi-part response has been decoded. `false` means feed more frames.
    public let complete: Bool
    /// The 0-100 decode completion percentage. Meaningful while `!complete`; `100` once complete.
    public let progress: Int
    /// The serialized batch-signature response, once `complete`; `nil` otherwise.
    public let data: Data?
    /// The signing device's reported firmware version, once `complete` and when the response
    /// envelope carried it; `nil` otherwise. See this type's provenance note above.
    public let firmwareVersion: KeystoneFirmwareVersion?

    /// Creates a `KeystoneBatchDecodeResult`.
    public init(complete: Bool, progress: Int, data: Data?, firmwareVersion: KeystoneFirmwareVersion?) {
        self.complete = complete
        self.progress = progress
        self.data = data
        self.firmwareVersion = firmwareVersion
    }
}
