# Plan C mini-spec — the batched trial-decrypt kernel (parked L4a, revived)

> **Status:** **GO (Lukas, 2026-07-05) — as v0.5's opening lever.** C0 immediately;
> C1 opens the v0.5 branch after the v0.4 close-out.
> Original gate line follows: Written per v0.4 plan Task 14 Step 1:
> *"if scan/decrypt now > 55% of wall on either device, write the Plan C
> mini-spec and STOP for approval."* The trigger fired on every device measured.
>
> **Recommendation up front: GO, as v0.5's opening lever** — not a v0.4 addition.
> v0.4 ships now (graft + batch, correctness gate closed); Plan C is a new
> compute kernel with its own measurement phase and deserves its own version.

## 1 · Why now — the trigger, quantified

v0.4 removed the tree-build work. What remains, fleet-wide, is trial
decryption — checking every on-chain ciphertext against the wallet's keys:

| device | v0.4 total | scan share | what a perfect persist lane would still leave |
|---|---|---|---|
| Mac M4 | 19.8 s | ~54 % of wall-clock is scan-stage | ~13 s |
| iPhone A18 | 55.4 s | 94.8 % | ~44 s |
| iPad A14 | 117 s | 94 % | ~90 s |
| iPad A10 | 354 s | 97 % | ~290 s |

The A14 row is the proof-by-embarrassment: v0.4 gave it only −13 % because the
same absolute persist win dilutes into a scan-dominated wall. **The mid-tier
fleet gains more from a 2–3× decrypt kernel than it gained from all of v0.4.**

## 2 · What trial decryption actually costs (the model C0 must confirm)

Per orchard action, per scan (single-account wallet):

1. Parse the compact action (epk decompress, cmx/nullifier field checks) — cheap.
2. **TWO Diffie–Hellman scalar multiplications** — `[ivk]·epk` for the External
   AND Internal scope ivks (zcash_client_backend scanning.rs:305/320 loops both
   scopes). Each is a ~255-bit variable-base Pallas mult. **This is the money.**
3. Batch affine-normalization of the shared secrets — upstream's
   `zcash_note_encryption::batch` already amortizes ONE inversion per batch. ✓
4. KDF (Blake2b) + ChaCha20 over 52 bytes + plaintext validity check — cheap;
   the expensive continuation (diversifier → g_d, cmx recompute) only runs on
   plaintexts that parse, i.e. ~never for foreign outputs.

Sapling outputs: same shape, two Jubjub mults. Estimated DH share of scan
compute: **80–90 %** (C0 measures the real number).

## 3 · What is already done or already DEAD (do not re-litigate)

- **Decrypt-ahead / persistent runner / deeper overlap: NO-GO** (2026-06-17
  spike, killed at Phase 0). All *orchestration* levers around decryption are
  falsified: write-behind already overlaps decrypt(N+1) with persist(N); depth>1
  measured 1.26× SLOWER on M4. The spike's own verdict names the survivor:
  *"the honest decrypt lever remains kernel work-reduction (parked L4a /
  column-ECDH), not orchestration."*
- **Runner/batch sizing: settled.** One `BatchRunner` per 10k-block chunk
  (config.rs `scan_batch_target_ms=None`); upstream's batch module already
  shares the inversion for point normalization.
- **Rayon parallelism: already on** (all cores, spawn_fifo pool).

Plan C therefore proposes exactly one thing: **a faster inner loop for N
same-scalar variable-base multiplications** — the "column-ECDH" idea L4a parked
on 2026-06-12, now revived with a technique v0.4 has already production-proven.

## 4 · The levers

### C1 — lockstep-affine batched DH (the core; Plan B's trick, retargeted)
All N epks in a batch are multiplied by the SAME fixed scalar (the ivk). A
double-and-add ladder therefore takes **identical steps in every lane** — no
divergence — which is exactly the shape batch-affine Sinsemilla exploits: march
all lanes one ladder step at a time, and per step share ONE Montgomery batch
inversion across the whole batch, using cheap affine formulas (~3–5 field muls
per lane-step) instead of projective ones (~8–14). Same recurrence discipline,
same poison-mark degenerate handling, same rayon chunking as
`batch_sinsemilla.rs`. Paper arithmetic says ~3× fewer field muls; the v0.4
Sinsemilla kernel delivered 12× on its probe with this exact pattern, so 2–3×
END-TO-END on the DH portion is the conservative planning number.

> **⚠ HONEST-BENCH CORRECTION (2026-07-05, post-wiring):** the first kernel
> probe reported 2.13× by timing `prepare_epk` + TWO `ka_agree` calls in the
> baseline against ONE kernel multiplication — and upstream's prepared path
> is **already wNAF-4 tabled** (`WnafBase`/`WnafScalar`, one table serving
> both scope ivks), which the paper arithmetic above ignored. The honest
> rewrite (`dh_kernel_bench`, per-N, prepare amortized out of both sides)
> measures on M4: **N=100 (production batch size, `BatchRunners::for_keys`)
> — wired shape 1.23×, batch-normalized 1.56×; N=10k — 1.44×/1.82×.** The
> per-point `to_affine()` in the first wiring cost one field inversion per
> lane per ivk (~1M+ per restore) and is fixed with `Point::batch_normalize`
> (one shared inversion per batch). Consequence: **C1 alone is a modest
> lever (~1.6× on DH ⇒ ≤ ⅓ of the DH share off scan), and C2's endomorphism
> split — which upstream's prepared path does NOT have — is now the
> make-or-break for §7's 2.5× mid-case.** Lukas's device A/B (65s OFF / 68s
> ON, fetch 22.7s vs ~10s the prior day = network-noise dominated) caught
> what the dishonest microbenchmark hid.

### C2 — endomorphism split (stacks on C1)
Pallas carries the Pasta cube-root endomorphism; a one-time GLV decomposition
of the FIXED ivk scalar halves the ladder length (two half-length scalars,
interleaved lanes). Decompose once per ivk per pass — amortized to zero. Gated
on pasta_curves exposing the endo constants at our pin (verify first; if not
exposed, C2 defers — C1 stands alone).

### C4 — NEON 4-way field mult (inside C1's lanes)
The original "SIMD" idea finally has a target that upstream hasn't already
batched: 4 lanes of Montgomery multiplication under C1's lockstep. Strictly
optional, measured tier by tier; the v0.4 lesson (NEON dropped — nothing left
to feed) applies in reverse here: C1 CREATES the uniform lanes NEON wants.

### Explicitly NOT proposed
- GPU (banked; the A10 killed it, and Plan A shrank its target once already).
- Protocol/server-side skipping (nullifier-first, decrypt-outsourcing) — real
  v0.5 candidates, but different risk class (privacy/protocol) — separate spec.
- Any change to sapling/orchard crypto semantics: byte-identical outcomes only.

## 5 · The swap-point (the one genuinely hard decision)

The DH happens INSIDE `zcash_note_encryption::batch` (invoked by upstream's
`BatchRunner`); there is no injection seam. Options:

| option | shape | verdict |
|---|---|---|
| (a) **fork `zcash_note_encryption`** (0.4.1, small crate), add a batched-DH backend behind a feature, `[patch]` the workspace | surgical, KAT-gated byte-identical; precedent = our shardtree fork that later upstreamed cleanly (PR #181 pattern) | **recommended** |
| (b) upstream seam PR first | right long-term, wrong critical path (weeks of review latency; same code either way) | do AFTER (a) proves the win, as the upstreaming follow-up |
| (c) own scan driver bypassing upstream scanning | huge blast radius, re-implements audited code | rejected |

## 6 · Phases + gates (each behind its own switch, v0.4 discipline)

- **C0 — measure first (½ day): ✅ DONE 2026-07-05, GATE PASSED — DH share 92.4%**
  (M4 release, 10k real-epk actions × 2 ivks: full upstream 108.5 µs/action,
  DH-only 100.2 µs/action; probe = `batch_ecdh.rs::decrypt_bench`). The kernel
  target is effectively the whole scan cost; §7's projections are conservative.
  Original plan text: in-crate `decrypt_bench` probe (the
  `combine_bench` pattern): 10k fabricated foreign actions (the T10b testkit
  fabricator) × 2 ivks; measure (i) full upstream batch decrypt, (ii) DH-only
  loop → the true DH share + µs/action on M4. **Gate: DH share ≥ 60 % or Plan C
  is re-scoped/killed cheaply.**
- **C1 — lockstep kernel (the weekend-sized core):** standalone
  `batch_ecdh.rs` + KAT vs upstream (10k debug / 100k release `#[ignore]`,
  byte-identical shared secrets) → fork wiring behind `batch_decrypt`
  (default OFF) → CLI/bench toggles ride the existing plumbing.
  **Gate: KAT + semantic oracle (found-notes set identical) + A/B ≥ +15 % total
  on one iOS-class device.**

  **❌ C1 PRODUCTION VERDICT (2026-07-05, gate FAILED — lever stays default
  OFF, kernel retained as instrument + record).** Wired end-to-end and
  byte-identical (KATs green; fire counters prove 100 % kernel coverage:
  2,410,514 / 2,410,514 lanes, 23,446 calls ≈ the `for_keys(100)` batch
  shape). The in-pass timer (`batch_dh_s`, cross-thread) then measured, on
  the M4 reference wallet (113 k blocks, interleaved runs):
  - per-item (OFF): **dh_s ≈ 149.6 / 145.7 s → 62 µs/lane** — validates the
    honest microbench baseline (71 µs), and reveals DH is BIG (~150 core-s
    inside a ~28 s scan wall — ~5–6 decrypt threads run concurrently);
  - lockstep kernel (ON): **dh_s ≈ 210 s → 87 µs/lane — 1.4× SLOWER in
    production**, the opposite of the single-threaded microbench (1.56×
    faster). Same code, same batch width: under real concurrency the
    kernel's per-call allocations + serial batch-inversion chains lose to
    the per-item wNAF walk, which is allocation-free and cache-resident.
    (Why Plan B's identical trick DID ship: `batch_sinsemilla` runs on its
    own dedicated pool at ~10 k-wide batches; upstream fixes decrypt at
    N≈103 and shares the scan threads.)
  - end-to-end wall: WASH in both directions on M4 (scan stage has ≥60
    core-s of slack — DH is off the M4 critical path either way).
  - device note: on A18 (6 cores, ~297 k-block wallet) DH plausibly
    saturates — the kernel's +40 % DH cost may explain part of Lukas's
    65 s→68 s ON regression (fetch noise explains the rest). The new
    `batch_dh_s` / `kernel_lanes` bench.json rows measure this directly on
    device; one OFF/ON bench-ios pair decides.
  **Consequence for C2:** endo-on-top-of-the-lockstep-kernel is DEAD (it
  halves the ladder of a kernel that loses on memory behavior, not
  arithmetic). C2 re-scopes to **endo-on-the-per-item path**: GLV-split the
  ivk once per pass, ζ-map the epk's existing wNAF table (8 field muls),
  walk two half-width scalars — allocation-free, per-item shape preserved,
  upstream-PR-able. Honest ceiling ~1.6–1.8× on DH; transfers to wall only
  where DH saturates cores (iOS tier, per the device reading above — gate
  C2 on Lukas's `batch_dh_s` rows).

  **❌❌ PLAN C CLOSED (2026-07-05 late night — Lukas's A18 firestats pair
  killed C2's premise too).** The device rows (same wallet, 297 k blocks,
  853 k orchard actions → 1,706,932 lanes = every action × 2 keys):
  - **OFF** (thermally throttled run — enhance 20.8 s and scan 114.9 s vs
    the 62.2 s healthy baseline an hour earlier): `batch_dh_s = 155.3 s`,
    91.0 µs/lane. DH is REAL on the phone — biggest compute block in the
    pass.
  - **ON** (healthy state, scan 59.7 s): `batch_dh_s = 227.1 s`,
    133.0 µs/lane, kernel fired on 100 % of lanes. Kernel ≥1.46× slower
    per lane than the per-item path measured in a WORSE thermal state —
    same-state realistically ~2×, worse than the Mac's 1.4× (E-cores have
    less cache/bandwidth for the allocation-heavy kernel).
  - **The C2 killer — the wall-transfer factor is ZERO on A18 too:** the
    same-state comparison (healthy OFF scan 60.5 s on the per-item path vs
    healthy ON scan 59.7 s carrying ~+140 EXTRA core-s of kernel DH) shows
    the scan wall does not move. DH runs in slack on BOTH tiers; any
    per-mult speedup (C1's or C2's) buys ~0 wall seconds fleet-wide.
  **Verdict: Plan C is closed under its own C0-style discipline** ("killed
  cheaply" — three device runs + the in-pass timer did it). The kernel,
  KATs, counters and timer stay in-tree as instrument + record;
  `batch_decrypt` stays default OFF permanently. **What the instruments
  revealed for v0.5's re-aim:** the scan wall (60 s A18 / 29 s M4,
  bound="scan" always) is set by the scan lane's SERIAL critical path
  (per-chunk decode → tree feed → stash chaining), not by decrypt compute
  — profile THAT (per-chunk stage timers, the census pattern again) and
  attack the top item. Also observed on device, unexplained: `enhance_s`
  swings 1.1 → 11.0 → 20.8 s across runs (bigger than fetch on the phone)
  — worth a look in the same instrumentation pass.
- **C2 — endo split:** stacked, own toggle, same KAT. Gate: measured stack gain.
- **C3 — fleet A/B + defaults:** the same four-device sweep v0.4 just ran;
  defaults per device class on the same ≥ +10 % rule.

## 7 · What it buys (projected, C0 to confirm)

Assume DH = 85 % of scan compute and a 2.5× kernel (C1+C2 mid-case):

| device | v0.4 today | Plan C projection | note |
|---|---|---|---|
| Mac M4 | 19.8 s | **~13–15 s** | approaching the fetch floor |
| iPhone A18 | 55.4 s | **~30–35 s** | halves the phone restore again |
| iPad A14 | 117 s | **~60–70 s** | bigger win than all of v0.4 gave it |
| iPad A10 | 354 s | **~210–230 s** | hits its own 216 s FETCH wall — the radio becomes the bottleneck; Plan C is the last CPU lever that matters on this tier |

Headlines if it lands: **Mac ≈ 15 s, iPhone ≈ 30 s, every current-gen device
under a minute** — and the industry-first line moves from "under a minute on a
phone" to "under half a minute."

## 8 · Cost, risk, and the honest caveats

- Effort: C0 ½ day; C1 ≈ one weekend (the batch_sinsemilla experience halves
  it: same recurrence/KAT/toggle skeleton); C2 1–2 days; C3 = device time.
- Risk: LOW for correctness (byte-identical KAT + oracle; read-only compute;
  wrong math = missed/false notes which the semantic oracle catches
  immediately). MEDIUM for payoff (the 12× Sinsemilla probe shrank to +15.7 %
  at production scale — Amdahl applies here too, but scan's 94 % share is a
  far bigger target than persist's remainder was).
- Maintenance: a second pinned fork (zcash_note_encryption) until upstreamed —
  the shardtree fork shows the lifecycle works.
- Beer-ledger disclosure ☺: if Plan C becomes v0.5's winning lever, it is a
  COMPUTE-TRICK — which scores the v0.5 flavor tiebreak for Lukas. The
  protocol-side candidates (nullifier-first et al.) remain the skip-the-work
  counterweight; v0.5's own spec will run both to ground.

## 9 · Decision requested

1. **GO / NO-GO** on Plan C as scoped above.
2. **Ship vehicle:** v0.5 opener (recommended) or v0.4.1 fast-follow.
3. If GO: C0 runs immediately (no device time needed); C1 starts on the C0
   gate's numbers.
