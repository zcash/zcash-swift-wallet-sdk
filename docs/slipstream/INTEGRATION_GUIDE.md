# Integrating Slipstream — the guidebook

Slipstream is a high-performance sync engine for Zcash light wallets: a Rust core that
syncs ~12× faster than the reference `CompactBlockProcessor` pipeline (measured on-device:
a 269k-block mainnet restore went from 25:11 to 2:05 on an A14 iPad), while writing the
**same wallet database** through the same published librustzcash crates.

This guide teaches you how to integrate it **correctly and with ease**. The design intent
matters more than any single API: **the engine owns wallet truth; your app renders it.**
Every number the engine exports — progress, balances, the recovery flag, spendability — is
already correct at every phase. The bugs this SDK's history is made of came from clients
(and earlier SDK layers) re-deriving those numbers themselves. Don't. The second half of
this guide is a contract-by-contract tour of what you may rely on and what you must never
compute on your own.

**Audience:** iOS/macOS app developers using `ZcashLightClientKit`. (Building a non-Swift
host — Kotlin, a CLI, a daemon? See [§14](#14-non-swift-hosts) — the engine has a
host-agnostic C/SQL contract and this SDK is just one consumer of it.)

---

## 1. The one-decision integration

`SlipstreamSynchronizer` implements the SDK's public `Synchronizer` protocol — the same
protocol `SDKSynchronizer` (the classic engine) implements. Same `Initializer`, same
`data.db`, same events, same everything. **Choosing the engine is one line:**

```swift
let initializer = Initializer(/* …identical config either way… */)

// Classic engine:
let synchronizer: Synchronizer = SDKSynchronizer(initializer: initializer)

// Slipstream:
let synchronizer: Synchronizer = SlipstreamSynchronizer(initializer: initializer)
```

Because both engines share the wallet database and the protocol, you can ship them behind
a runtime flag and A/B or stage the rollout (this is exactly how the Zodl wallet shipped
it):

```swift
let synchronizer: Synchronizer = featureFlags.useSlipstream
    ? SlipstreamSynchronizer(initializer: initializer)
    : SDKSynchronizer(initializer: initializer)
```

Switching a user between engines requires no migration — the next engine picks up the same
`data.db`. The prefer-callbacks and prefer-Combine wrappers (`ClosureSDKSynchronizer`,
`CombineSDKSynchronizer`) wrap **any** `Synchronizer`, so they carry Slipstream unchanged.

Rule of thumb for the rest of your integration: **if your code would work against
`SDKSynchronizer`, it works against Slipstream.** The differences are that sync is much
faster, and that several values you might have been tempted to compute yourself
(restore-time balances, progress, "is this a restore?") are now engine-guaranteed.

## 2. Setup — the `Initializer`

One `Initializer` describes where the wallet lives and how to reach the network:

```swift
let initializer = Initializer(
    cacheDbURL: nil,                        // legacy migration input; nil for new apps
    fsBlockDbRoot: fsBlockDbRootURL,        // block-cache dir (used by the classic engine)
    generalStorageURL: generalStorageURL,   // SDK general storage dir
    dataDbURL: dataDbURL,                   // THE wallet database (shared by both engines)
    torDirURL: torDirURL,                   // Tor state dir (provisioned even if Tor is off)
    endpoint: LightWalletEndpoint(address: "zec.rocks", port: 443, secure: true),
    network: ZcashNetworkBuilder.network(for: .mainnet),
    spendParamsURL: spendParamsURL,         // Sapling params (auto-downloaded when missing)
    outputParamsURL: outputParamsURL,
    saplingParamsSourceURL: .default,
    alias: .default,                        // suffix-isolates all paths; use for multi-wallet
    loggingPolicy: .default(.debug),        // inject your logger here (see §13)
    isTorEnabled: false,                    // initial Tor posture (changeable at runtime, §10)
    isExchangeRateEnabled: false
)
```

Notes:
- **Paths**: put them under your app's Documents/Application Support; the SDK creates
  what's missing. `alias` namespaces every path — two synchronizers may coexist only with
  distinct aliases.
- **The endpoint** is the lightwalletd server. Slipstream uses its own Rust-side transport
  for sync (concurrent block streams; Tor circuits for the privacy-relevant calls), and
  the SDK's gRPC stack for submission and queries.
- The `Initializer` constructor never throws; configuration errors surface from
  `prepare()`.

## 3. Lifecycle — `prepare` → `start` → `stop`

### 3.1 `prepare(with:walletBirthday:name:keySource:)`

Call once per launch, before anything else. It initializes/migrates the database, creates
the account when needed, and opens the engine.

```swift
let result = try await synchronizer.prepare(
    with: seedBytes,          // nil = open existing wallet without touching keys
    walletBirthday: birthday, // see the table below
    name: "Account 1",
    keySource: nil
)
guard result == .success else { /* .seedRequired: a migration needs the seed — ask the user */ }
```

**You do not tell the SDK whether this is a new wallet, a restore, or a routine open — it
derives the flow** (there is deliberately no "init mode" parameter):

| Situation | What you pass | What happens |
|---|---|---|
| Routine app launch (wallet exists) | `seed` optional, any birthday | Account exists → opened as-is; nothing is created. Idempotent. |
| Brand-new wallet | fresh `seed`, `walletBirthday: nil` | The engine picks a reorg-safe recent height (server tree state at tip−100); no recovery phase. |
| Restore from seed | `seed`, `walletBirthday: <user's birthday height>` | Account created with `recover_until` = current chain tip → the whole `[birthday…tip]` backfill is tracked as a **recovery** (see §5.3). Works offline too: the engine falls back to its bundled-checkpoint estimate, so the restore never loses its "restoring" identity. |

Safety built in: restoring a **different** seed over an existing wallet throws
`ZcashError.initializerSeedMismatch` instead of silently opening the old wallet (which
would show balances you cannot spend). Treat it as "wipe first, then restore" (§11.3).

A deliberate re-scan is **not** an init mode — that's `rescanFrom(height:)`/`rewind(_:)`
(§11).

### 3.2 `start(retry:)` and `stop()`

```swift
try await synchronizer.start(retry: false)   // begins syncing + follows the chain tip
synchronizer.stop()                          // synchronous, safe to call anytime
```

- `start` after `prepare`, typically on foreground. Slipstream runs one sync pass to the
  tip, then stays live: it follows new blocks (~75 s cadence) and watches the **mempool**
  for 0-conf transactions addressed to the wallet. You never re-poke it.
- `stop` on background (`didEnterBackground`), `start` on foreground. A stop→start hop is
  cheap: the scan position is durable in `data.db`, and rapid stop/start ordering is
  handled internally — you can call them naively.
- Calling `start` before `prepare` throws `ZcashError.synchronizerNotPrepared`.
- After a failure surfaces as `SyncStatus.error` (§5.2), calling `start` again is the
  retry — the engine resumes from its persisted position, never from scratch.

## 4. Observing the wallet

Two Combine publishers carry everything (thread-safe; deliver on internal queues — hop to
the main actor for UI):

```swift
synchronizer.stateStream    // AnyPublisher<SynchronizerState, Never> — full snapshots
synchronizer.eventStream    // AnyPublisher<SynchronizerEvent, Never> — edge signals
synchronizer.latestState    // sync read of the most recent SynchronizerState
```

`SynchronizerState` fields and what to do with them:

| Field | Contract | Use it for |
|---|---|---|
| `syncStatus` | see §5.1 | The sync UI state machine |
| `accountsBalances` | **phase-correct at all times** (§6) | Balance display, verbatim |
| `latestBlockHeight` | chain tip as known to the wallet (persisted tip immediately on cold launch; live tip once syncing) | "Height N" labels, confirmations math |
| `fullyScannedHeight` | contiguous-from-birthday frontier | Rarely needed by apps |
| `isRecovering` | see §5.3 | "Restoring…" UI + provisional-data posture |

### 5.1 `syncStatus` and progress

```swift
public enum SyncStatus { case unprepared, syncing(Float, Bool), upToDate, stopped, error(Error) }
```

- `.syncing(progress, areFundsSpendable)` — `progress` is **the** progress value, 0…1.
  The engine guarantees: it never moves backwards; a cold launch of a synced wallet starts
  at ~1.0 (never a 0% flash); an interrupted restore **resumes at its true position**
  after relaunch; importing an account with an older birthday resets it so the re-scan
  reads as a genuine 0→100% climb. **Render it verbatim. Never compute progress from
  heights** — every height-ratio formula a client invents is wrong in at least one of
  those situations.
- `areFundsSpendable` flips true early in a restore (recent blocks are scanned first —
  "spend before sync"), so users can spend while history backfills.
- `.upToDate` — synced to tip; the engine keeps following (you'll see `.syncing` blips as
  new blocks arrive, then `.upToDate` again).
- `.error(err)` — the pass failed terminally (after the engine's internal retries for
  transient network trouble). Show a retry affordance → `start()`.
- On a fresh wallet with nothing yet, cold launch reports `.unprepared`-then-`.syncing`;
  a synced wallet's cold launch reports a warm, truthful state **immediately from
  `prepare()`** — you never need to cache last-known values yourself.

### 5.2 `eventStream`

```swift
public enum SynchronizerEvent {
    case foundTransactions([ZcashTransaction.Overview], CompactBlockRange?)
    case minedTransaction(ZcashTransaction.Overview)
    case storedUTXOs(_ inserted: [UnspentTransactionOutputEntity], _ skipped: [UnspentTransactionOutputEntity])
    case connectionStateChanged(ConnectionState)
}
```

The one that matters day-to-day is **`foundTransactions`**: treat it as *"the transaction
set changed — re-fetch what you display."* It fires exactly when something changed (a new
transaction scanned or enhanced, a mempool 0-conf hit, a pending transaction mined or
expired, a just-broadcast send stored, restore visibility advancing) and is quiet
otherwise, so it is safe to bind directly to a list refresh. The transactions attached to
the event are a convenience (the 50 most recent, already visibility-filtered) — re-query
via §7 if you need more. After you send, the pending row appears via this event within a
poll tick (~2 s); you don't need to inject it into your UI manually.

### 5.3 `isRecovering` — the restore contract

`true` while the wallet is inside a restore/backfill window (formally: queued scan work
remains below the account's `recover_until` height). It is **durable and derived** — it
survives app kills mid-restore (recomputed from the database at open, correct from the
very first state emission), self-corrects across rewinds, and is force-released if a pass
dies (an error can never wedge your "Restoring" UI).

What your app should do with it:
- Show a "Restoring wallet…" treatment instead of the regular sync indicator.
- Trust balances and the transaction list **as delivered** — during recovery the SDK
  already serves recovery-safe values for both (see §6/§7). You don't hide anything
  yourself; you just *label* the phase.
- Don't persist your own "user is restoring" flag. This field is strictly better: the
  truth, not a guess.

## 6. Balances — guaranteed, don't improvise

```swift
let balances = try await synchronizer.getAccountsBalances()  // or state.accountsBalances
```

`AccountBalance` carries the shielded pools (`saplingBalance`, `orchardBalance` — each
with `spendableValue`, `changePendingConfirmation`, `valuePendingSpendability`) and
`unshielded`. The engine guarantees, at every phase:

- **Never over-shows.** During a restore, naive balance math transiently *inflates* (a
  received note is counted before the spend that consumed it is scanned — the classic
  "phantom 8 ZEC" class). Slipstream serves a recovery-safe balance instead: the sum of
  fully-reconciled transaction deltas, which climbs monotonically to the true total and
  can only ever under-show momentarily, never over-show.
- **Spendable is masked until the chain tip is proven.** Until the current run has
  refreshed the tip, "spendable" would be a claim about a chain state the wallet hasn't
  verified this session — the engine moves those funds to `valuePendingSpendability` for
  the first seconds after a cold start, then releases. Render what you get; a brief
  "pending" shimmer at launch is correct behavior, not a bug to paper over.

**Never** sum transactions, notes, or UTXOs yourself to make a balance; never cache and
serve your own last-known balance across the restore phase. Both re-create solved bugs.

## 7. Transactions & history

```swift
await synchronizer.transactions                    // all, newest first (visibility-filtered)
try await synchronizer.allTransactions(from: tx, limit: 50)   // paging by anchor
synchronizer.paginatedTransactions(of: .all)       // paginated repository (.all/.sent/.received)
try await synchronizer.getMemos(for: tx)           // decrypted memos
await synchronizer.getRecipients(for: tx)          // outgoing recipients
await synchronizer.getTransactionOutputs(for: tx)
try await synchronizer.fetchTxidsWithMemoContaining(searchTerm: "invoice")
```

Contracts worth knowing:
- `ZcashTransaction.Overview.state` is populated (`.pending`, `.confirmed`, `.expired`, …)
  against the current height — a 0-conf mempool receive arrives as *pending/receiving*,
  not "received".
- **Restore visibility:** during recovery, a transaction whose input-spend hasn't linked
  yet reads misleadingly (a self-send's change looks like a phantom "+receive"). The SDK
  holds exactly those provisional rows back and reveals each one the moment its history
  linkage is final — genuine receives appear immediately, mid-restore. Outside recovery,
  nothing is ever held. You don't implement any of this; just render the list you're
  given and refresh on `foundTransactions`.
- The list is DB-backed and cheap to re-fetch; don't build a shadow store.

## 8. Sending

The flow is propose → create/sign → submit, and it is identical on both engines:

```swift
// 1. Propose (fee calculation, note selection — nothing is spent yet)
let proposal = try await synchronizer.proposeTransfer(
    accountUUID: account, recipient: recipient, amount: Zatoshi(10_000), memo: memo)

// (or) proposeShielding(accountUUID:shieldingThreshold:memo:transparentReceiver:)  // t→z
// (or) proposefulfillingPaymentURI(_:accountUUID:)                                 // ZIP-321

// 2+3. Create + broadcast (seed-based signing)
let stream = try await synchronizer.createProposedTransactions(
    proposal: proposal, spendingKey: usk)
for try await result in stream {
    switch result {
    case .success(let txId): ...
    case .grpcFailure(let txId, let error): ...     // network refused — nothing on chain
    case .submitFailure(let txId, let code, let desc): ...  // server rejected
    case .notAttempted(let txId): ...               // earlier tx in the batch failed
    }
}
```

- A proposal can span multiple transactions; iterate the whole stream and stop treating
  the send as final only when every element succeeded.
- Submission is multi-server resilient (the SDK re-broadcasts through fallback servers)
  and reports "already known to the network" as success.
- **Hardware wallets (PCZT):** `createPCZTFromProposal` → `redactPCZTForSigner` (strip
  before showing/transporting) → device signs → `PCZTRequiresSaplingProofs` /
  `addProofsToPCZT` → `createTransactionFromPCZT(pcztWithProofs:pcztWithSigs:)`. Same
  result stream.
- After a successful submit, the pending row surfaces via `foundTransactions` on the next
  tick — no manual insertion.

## 9. Accounts, addresses, keys

```swift
try await synchronizer.listAccounts()
try await synchronizer.importAccount(ufvk:seedFingerprint:zip32AccountIndex:purpose:name:keySource:birthday:)
try await synchronizer.deleteAccount(uuid)
try await synchronizer.isSeedRelevantToAnyDerivedAccount(seed: seed)

try await synchronizer.getUnifiedAddress(accountUUID: account)
try await synchronizer.getSaplingAddress(accountUUID: account)
try await synchronizer.getTransparentAddress(accountUUID: account)
try await synchronizer.getCustomUnifiedAddress(accountUUID: account, receivers: [.orchard, .sapling])
try await synchronizer.getSingleUseTransparentAddress(accountUUID: account)
```

- **Keys never enter the engine.** Seeds/UFVKs stay in your keychain and the SDK's key
  layer; the engine syncs with viewing capability only. Derivation is `DerivationTool`.
- `importAccount` (UFVK, view-only — e.g. a hardware wallet) with an older `birthday` on
  an already-synced wallet triggers the right re-scan automatically, the progress bar
  correctly climbs 0→100% for it, and the account's backfill is tracked as a recovery. If
  the device is offline at import time, the recovery identity is preserved (engine
  fallback) — no special handling needed.

## 10. Server, network, Tor

```swift
try await synchronizer.switchTo(endpoint: newEndpoint)  // no-op if identical; restarts the pass if running
await synchronizer.evaluateBestOf(endpoints: candidates, ...)  // latency-ranked reachable servers
try await synchronizer.latestHeight()                   // live tip straight from the server
try await synchronizer.tor(enabled: true)               // runtime Tor posture
try await synchronizer.exchangeRateOverTor(enabled: true)
await synchronizer.isTorSuccessfullyInitialized()
synchronizer.refreshExchangeRateUSD()                   // result arrives on exchangeRateUSDStream
try await synchronizer.httpRequestOverTor(for: request, retryLimit: 3)
```

Tor semantics with Slipstream: bulk block download stays direct (full speed); the
privacy-relevant calls — tip queries, tree states, restore provisioning, transaction
fetches — ride isolated Tor circuits. If Tor is requested but fails to bootstrap, the
engine degrades to *offline behavior*, never to a silent direct connection.

## 11. Maintenance operations

```swift
// 11.1 Deliberate re-scan from a height (keeps keys/accounts):
try await synchronizer.rescanFrom(height: someHeight)   // then start()

// 11.2 Rewind (publisher completes when done; engine must be stopped):
synchronizer.rewind(.birthday)   // .quick / .birthday / .height(h) / .transaction(tx)

// 11.3 Full wipe — deletes the wallet database (NOT the seed; that's yours):
synchronizer.wipe()              // then prepare() again to start over

// Birthday helpers for restore UX:
synchronizer.estimateBirthdayHeight(for: dateUserPicked)
synchronizer.estimateTimestamp(for: height)
```

`wipe` + `prepare(seed:birthday:)` is the correct "restore a different wallet" sequence
(see the seed-mismatch guard in §3.1).

## 12. Transparent extras

```swift
try await synchronizer.refreshUTXOs(address: tAddr, from: height)
try await synchronizer.checkSingleUseTransparentAddresses(accountUUID: account)
try await synchronizer.updateTransparentAddressTransactions(address: tAddrString)
try await synchronizer.fetchUTXOsBy(address: tAddrString, accountUUID: account)
```

Transparent funds are discovered during sync automatically; these exist for explicit
refresh flows (e.g. after receiving to a single-use t-address).

## 13. Logging & diagnostics

- Inject your logger via `Initializer(loggingPolicy: .custom(yourLogger))`. Never
  `print` in SDK-adjacent code. Slipstream logs are prefixed `[slipstream]` and the
  Rust engine logs through the same OS facility — a device log carries the full story
  (pass lifecycle, recovery flips, provisioning decisions).
- `synchronizer.debugDatabase(sql:)` runs read-only SQL against `data.db` — invaluable in
  the field, not for production features.
- `getTreeState(height:)` fetches a server tree state (serialized protobuf) — a
  power-user/debug API.

## 14. Non-Swift hosts

The Swift layer in this repo is one consumer of a deliberately host-agnostic contract.
A Kotlin/JVM, CLI, or daemon host integrates against:

- **Handle FFI:** `zcashlc_slipstream_open / start / stop / free` (lifecycle),
  `snapshot` (poll: state, blessed `progress_permille`, `is_recovering`, `tip_fresh`,
  `tx_set_version`, `stalled_seconds`, counters), `drain_events` (edge ring),
  `wallet_summary` (phase-correct balances, internally cost-rationed — call it every
  tick), `notify_tx_change` (post-broadcast poke), `restore_anchor` (handle-less wallet
  provisioning with offline fallback).
- **Versioned SQL views** on the shared wallet DB (`slipstream_v_tx_reconciled`,
  `slipstream_v_recovery_balance`) plus the standard librustzcash schema.
- The host's whole job is the loop this SDK's `SlipstreamSynchronizer` implements: poll
  the snapshot on a timer, map it to your UI idiom (Combine here, Flow on Kotlin), fetch
  + publish transactions when `tx_set_version` moves or your recovery filter flips, and
  render balances from the summary. The snapshot is truthful from `open()` — do not add
  warm-up compensation.

See `docs/slipstream/plans/ENGINE_API_V2.md` (the contract, with vetoes and amendments)
and the engine repo's `REVIEWING.md` (module map). The `slipstream watch` CLI in the
engine repo is a complete reference host in ~200 lines.

## 15. Client responsibilities — the checklist

**Do:**
- Call `prepare()` once per launch; `start()`/`stop()` on foreground/background.
- Drive ALL sync UI from `stateStream`; refresh lists on `foundTransactions`.
- Render `syncStatus.syncing`'s progress and `accountsBalances` verbatim.
- Use `isRecovering` for the "Restoring" label and provisional-data posture.
- Handle `.error` with a retry affordance that just calls `start()` again.
- Keep the seed in your secure storage; pass it only to `prepare`, spending keys only to
  the create/sign calls.
- On restore-of-a-different-seed: `wipe()` first (the seed-mismatch guard will refuse
  otherwise — by design).

**Never:**
- Compute progress from block heights, or smooth/floor/clamp the reported progress.
- Compute balances from transactions/notes, or serve your own cached balance during a
  restore.
- Persist an "is restoring" flag (use `isRecovering`), or an init-mode choice (derived).
- Hide or re-order the transaction list to "fix" restore artifacts — the SDK already
  serves the correct visible set.
- Poll `getAccountsBalances()` in a hot loop for UI — `stateStream` already carries
  balances every tick; the direct call is for on-demand flows.
- Keep the engine running in the background indefinitely (mobile): stop on background.

## 16. Pitfalls we already hit so you don't have to

| Symptom you might build | The mistake | The correct move |
|---|---|---|
| Balance shows 8 ZEC mid-restore, settles to 4 | Reading raw note sums during recovery | Render `accountsBalances` as delivered — the engine's recovery balance never over-shows |
| Progress bar flashes 0% on every cold launch | Client-side height-ratio progress | Render the reported progress; it starts warm by contract |
| "Restoring" banner survives forever after an error | Own persisted restoring flag | `isRecovering` — the engine force-releases it on terminal states |
| Phantom "+1 ZEC received" rows during restore | Rendering the raw tx list mid-restore | The visible list is already filtered; refresh on `foundTransactions` |
| Sent tx never appears / appears twice | Manually inserting a pending row after submit | Do nothing — it arrives via `foundTransactions` within a tick |
| Wrong wallet's balance after a re-restore | Restoring a new seed over an existing DB | `wipe()` first; the `initializerSeedMismatch` guard exists to stop you |
| Sync "stuck" after brief server outage | Tearing the engine down on first error | Transient trouble is retried internally; only `.error` needs user-facing retry |

## 17. Quick API reference

| Area | Members |
|---|---|
| Lifecycle | `prepare(with:walletBirthday:name:keySource:)` · `start(retry:)` · `stop()` |
| Observation | `stateStream` · `eventStream` · `latestState` · `exchangeRateUSDStream` · `connectionState` · `alias` |
| Balances | `getAccountsBalances()` |
| History | `transactions` · `sentTransactions` · `receivedTransactions` · `allTransactions()` · `allTransactions(from:limit:)` · `paginatedTransactions(of:)` · `getMemos(for:)` · `getRecipients(for:)` · `getTransactionOutputs(for:)` · `fetchTxidsWithMemoContaining(searchTerm:)` |
| Sending | `proposeTransfer(…)` · `proposeShielding(…)` · `proposefulfillingPaymentURI(_:accountUUID:)` · `createProposedTransactions(proposal:spendingKey:)` |
| Hardware (PCZT) | `createPCZTFromProposal(…)` · `redactPCZTForSigner(pczt:)` · `PCZTRequiresSaplingProofs(pczt:)` · `addProofsToPCZT(pczt:)` · `createTransactionFromPCZT(pcztWithProofs:pcztWithSigs:)` |
| Accounts | `listAccounts()` · `importAccount(…)` · `deleteAccount(_:)` · `isSeedRelevantToAnyDerivedAccount(seed:)` |
| Addresses | `getUnifiedAddress(accountUUID:)` · `getSaplingAddress(accountUUID:)` · `getTransparentAddress(accountUUID:)` · `getCustomUnifiedAddress(accountUUID:receivers:)` · `getSingleUseTransparentAddress(accountUUID:)` |
| Server/network | `switchTo(endpoint:)` · `evaluateBestOf(…)` · `latestHeight()` · `tor(enabled:)` · `exchangeRateOverTor(enabled:)` · `isTorSuccessfullyInitialized()` · `refreshExchangeRateUSD()` · `httpRequestOverTor(for:retryLimit:)` |
| Maintenance | `rescanFrom(height:)` · `rewind(_:)` · `wipe()` · `estimateBirthdayHeight(for:)` · `estimateTimestamp(for:)` |
| Transparent | `refreshUTXOs(address:from:)` · `checkSingleUseTransparentAddresses(accountUUID:)` · `updateTransparentAddressTransactions(address:)` · `fetchUTXOsBy(address:accountUUID:)` |
| Debug | `debugDatabase(sql:)` · `getTreeState(height:)` · `enhanceTransactionBy(txId:)` |

---

*Further reading: `docs/slipstream/plans/ENGINE_API_V2.md` (the engine↔host contract),
`docs/SLIPSTREAM_DESIGN.md` (architecture), the engine repo
`github.com/LukasKorba/slipstream` (`README.md` versioning map, `REVIEWING.md` module
map, `cli/` reference host).*
