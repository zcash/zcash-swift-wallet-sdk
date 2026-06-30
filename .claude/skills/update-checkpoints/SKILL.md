---
name: update-checkpoints
description: >-
  Updates the bundled Zcash lightwallet checkpoint files under
  Sources/ZcashLightClientKit/Resources/checkpoints (mainnet + testnet). Use this
  whenever the user asks to update, refresh, regenerate, bump, or add new
  checkpoints, "run checkmate", or prepare checkpoints for a release — even if
  they don't name the exact directory. Downloads new GetTreeState checkpoints from
  the last stored checkpoint up to the chain tip for both networks, keeps only
  interval-aligned files, verifies them, adds a CHANGELOG entry, and commits.
---

# Update Zcash checkpoints

The SDK ships bundled chain checkpoints in
`Sources/ZcashLightClientKit/Resources/checkpoints/{mainnet,testnet}/<height>.json`.
They seed wallet birthday lookups, so they need refreshing periodically (typically
before a release) to add checkpoints for blocks mined since the last update.

This skill automates the established "Checkpoints updated" workflow: for each
network it downloads new tree-state checkpoints from the last stored checkpoint to
the current chain tip, keeps only the interval-aligned files, verifies them, records
them in `CHANGELOG.md`, and commits.

## How it works (the conventions baked into the scripts)

| Network | Lightwalletd host        | Interval | `network` value |
|---------|--------------------------|----------|-----------------|
| mainnet | `zec.rocks:443`          | `2500`   | `main`          |
| testnet | `testnet.zec.rocks:443`  | `10000`  | `test`          |

- **Start height = the highest `<height>.json` already on disk** for that network.
  The script resolves it automatically — never hardcode it.
- **Only interval-aligned checkpoints are committed.** `checkmate.py` also fetches
  the current chain tip (a non-aligned block); the driver deletes that file because
  the committed grid only contains multiples of the interval. (The handful of old
  non-aligned files like `419200.json` are historical activation-height checkpoints
  and are left untouched — the start height is far above them.)
- **The anchor file never changes.** `checkmate.py` re-downloads its start height;
  the driver restores that file afterwards so an already-committed checkpoint can't
  be corrupted by a transient network error. Runs are therefore purely additive.

## Prerequisites

`grpcurl` and `python3` must be on `PATH`. Check first:

```bash
command -v grpcurl python3
```

If `grpcurl` is missing, tell the user to `brew install grpcurl` rather than guessing.

## Workflow

Run all commands from the repo root. The scripts live in
`.claude/skills/update-checkpoints/scripts/`.

### 1. Download mainnet checkpoints

```bash
python3 .claude/skills/update-checkpoints/scripts/fetch_checkpoints.py mainnet
```

This prints a JSON summary (`anchor`, `added`, `added_count`, `new_max`,
`dropped_tip`). Note the `first_added`/`new_max` — you'll need them for the CHANGELOG
and commit message. `added_count: 0` means the chain hasn't advanced a full interval
since the last update and there's nothing new for mainnet.

### 2. Download testnet checkpoints

```bash
python3 .claude/skills/update-checkpoints/scripts/fetch_checkpoints.py testnet
```

### 3. Verify

This is the safety net: `grpcurl` writes through a shell redirect, so a failed query
can leave a half-written or error-filled `.json`. The verifier validates exactly the
files about to be committed — JSON shape, required keys, correct `network`, height
matching the filename, interval alignment, valid `hash`/trees, and that the new
heights extend the grid contiguously with no gaps and without modifying any
committed checkpoint.

```bash
python3 .claude/skills/update-checkpoints/scripts/verify_checkpoints.py
```

It must print `PASS`. If it prints `FAILED`, **do not commit** — go to
[Troubleshooting](#troubleshooting).

Also eyeball the working tree to confirm the change is additive and only touches the
checkpoints directories:

```bash
git status --short Sources/ZcashLightClientKit/Resources/checkpoints
```

You should see only new (`??`) `.json` files — no modified (` M`) or deleted ones.

### 4. Update CHANGELOG.md

Add a `## Checkpoints` section at the **end of the `# Unreleased` section** (just
before the first released `# x.y.z` heading). If a `## Checkpoints` section already
exists under `# Unreleased` (a prior unreleased update), merge into it — update the
ranges instead of adding a second section. Skip a network entirely if its
`added_count` was 0.

Use the first and last added file from each summary, with `...` between them, inside
four-backtick fences (matching prior entries):

````markdown
## Checkpoints

Mainnet

````
Sources/ZcashLightClientKit/Resources/checkpoints/mainnet/<first_added>.json
...
Sources/ZcashLightClientKit/Resources/checkpoints/mainnet/<new_max>.json
````

Testnet

````
Sources/ZcashLightClientKit/Resources/checkpoints/testnet/<first_added>.json
...
Sources/ZcashLightClientKit/Resources/checkpoints/testnet/<new_max>.json
````
````

### 5. Commit

Stage the new checkpoint files and the CHANGELOG, then commit. The repo's convention
for these commits is the literal title **`Checkpoints updated`** with a short range
summary in the body. If the current branch is `main`, create a topic branch first
(e.g. `update-checkpoints`) — `main` must stay clean per repo policy.

```bash
git add Sources/ZcashLightClientKit/Resources/checkpoints CHANGELOG.md
git commit -m "Checkpoints updated" -m "Mainnet <first_added> → <new_max> (interval 2500).
Testnet <first_added> → <new_max> (interval 10000).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

Do **not** push — leave that to the user.

### 6. Sanity-check the commit

Confirm the commit contains what you expect and nothing stray:

```bash
git show --stat HEAD
```

Verify: the file count matches `added_count(mainnet) + added_count(testnet) + 1`
(the +1 is `CHANGELOG.md`), every checkpoint path is interval-aligned, and
`CHANGELOG.md` is included. Report the final mainnet and testnet ranges to the user.

## Troubleshooting

**Verifier `FAILED` on a specific file (bad JSON / missing keys):** a `grpcurl` call
failed mid-run. Reset the working tree for that network and re-run its fetch — the
operation is additive and idempotent:

```bash
git checkout -- Sources/ZcashLightClientKit/Resources/checkpoints/<network>
git clean -f Sources/ZcashLightClientKit/Resources/checkpoints/<network>
python3 .claude/skills/update-checkpoints/scripts/fetch_checkpoints.py <network>
```

(`git clean -f` removes the untracked new files so the next run starts cleanly from
the committed anchor. Double-check the path so you don't clean anything else.)

**Verifier reports a gap or a modified committed file:** don't paper over it. A gap
can mean an intermediate `grpcurl` call silently failed; a modified anchor can mean a
genuine reorg or a path mix-up. Investigate before committing — reset as above and
re-run, and if it persists, check connectivity to the host.

**Connectivity check** (read-only, writes no files):

```bash
grpcurl zec.rocks:443 cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock
grpcurl testnet.zec.rocks:443 cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock
```

**Nothing to update:** if both networks report `added_count: 0`, the bundled
checkpoints are already current — tell the user and stop without a commit.
