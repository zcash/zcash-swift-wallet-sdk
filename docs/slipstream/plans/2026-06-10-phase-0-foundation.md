# Phase 0 — Foundation & Session Machinery: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
> Before starting ANY task: read `docs/slipstream/STATE.md` and `docs/slipstream/CONVENTIONS.md`.

**Goal:** A cargo workspace containing the empty-but-real Slipstream crates, with the multi-session machinery committed, and proof that the old SDK's build/test pipeline is unbroken (gate G0).

**Architecture:** Root `Cargo.toml` (libzcashlc) becomes a workspace root with two new members: `slipstream-core` (engine library, platform-neutral, holds only domain types for now) and `slipstream-cli` (dev harness binary). No existing rust/Swift code is touched except 4 lines in root `Cargo.toml` and a pointer section in `CLAUDE.md`.

**Tech stack:** Rust edition 2024 (toolchain 1.90, same as root), `thiserror 2`, `zcash_protocol 0.9` (already in tree), `tracing 0.1`, `clap 4`.

**File structure:**

```
Cargo.toml                          # MODIFY: + [workspace] section (4 lines)
slipstream/
  core/
    Cargo.toml                      # CREATE
    src/lib.rs                      # CREATE: crate root, module wiring
    src/config.rs                   # CREATE: EngineConfig, Endpoint + validation
    src/error.rs                    # CREATE: SlipstreamError
    src/events.rs                   # CREATE: Event, Snapshot, Bound, SyncMode
  cli/
    Cargo.toml                      # CREATE
    src/main.rs                     # CREATE: clap scaffold, `version` subcommand
CLAUDE.md                           # MODIFY: + Slipstream pointer section
docs/slipstream/STATE.md            # MODIFY: status updates per task
```

---

### Task 0.1: Branch, tracking issue, machinery commit

**Files:** none created (commits files already authored: `docs/slipstream/ROADMAP.md`, `STATE.md`, `CONVENTIONS.md`, this plan).

- [ ] **Step 1: Create the branch**

```bash
cd /Users/lukaskorba/Dev/Xcode/GitHub/LukasKorba/ZcashLightClientKit
git checkout main && git pull && git checkout -b slipstream
```
Expected: `Switched to a new branch 'slipstream'`

- [ ] **Step 2: Create the tracking issue**

```bash
gh issue create \
  --title "Slipstream: next-gen sync engine prototype" \
  --body "Multi-session prototype of a new Rust sync engine. Master roadmap: docs/slipstream/ROADMAP.md. Living state: docs/slipstream/STATE.md. Design: docs/SLIPSTREAM_DESIGN.md. All prototype commits reference this issue."
```
Expected: prints an issue URL ending in a number `N`.
**Fallback** if `gh` is unauthenticated: ask the user to create the issue, or temporarily use `0000`; either way record the number in `STATE.md` → "Tracking issue" section now.

- [ ] **Step 3: Record the issue number in STATE.md**

Edit `docs/slipstream/STATE.md`: replace `#TBD — created in T0.1` with the real number. Set T0.1 status to `done`, NEXT ACTION to T0.2. Append session-log line.

- [ ] **Step 4: Commit the machinery**

```bash
git add docs/slipstream/ docs/SLIPSTREAM_DESIGN.md docs/SYNC_PERFORMANCE_PROPOSAL.md
git commit -m "[#N] slipstream: add roadmap, state, conventions, phase-0 plan"
```

---

### Task 0.2: Cargo workspace + prove the FFI pipeline survives

**Files:**
- Modify: `Cargo.toml` (root)
- Create: `slipstream/core/Cargo.toml`, `slipstream/core/src/lib.rs` (placeholder)
- Create: `slipstream/cli/Cargo.toml`, `slipstream/cli/src/main.rs` (placeholder)

This task is FIRST because it carries the highest structural risk (build scripts).

- [ ] **Step 1: Inspect how the build scripts invoke cargo (read-only)**

```bash
grep -rn "cargo " Scripts/ | grep -v Binary
```
Note every invocation. If any runs a bare `cargo build` *from the repo root*, it still builds only the root package (root is a package directory), so no change is expected — but verify in Step 6, and if a script breaks, pin it with `-p libzcashlc` and record in the Decision Log.

- [ ] **Step 2: Add the workspace section to root `Cargo.toml`**

Append at the end of `/Users/lukaskorba/Dev/Xcode/GitHub/LukasKorba/ZcashLightClientKit/Cargo.toml`:

```toml
[workspace]
members = ["slipstream/core", "slipstream/cli"]
resolver = "3"
```

- [ ] **Step 3: Create the placeholder crates**

`slipstream/core/Cargo.toml`:
```toml
[package]
name = "slipstream-core"
version = "0.0.1"
edition = "2024"
rust-version = "1.90"
license = "MIT"
publish = false

[dependencies]
```

`slipstream/core/src/lib.rs`:
```rust
//! Slipstream sync engine core (platform-neutral).
//! See docs/SLIPSTREAM_DESIGN.md for the architecture and
//! docs/slipstream/ROADMAP.md for the build plan.

/// Crate smoke marker used by the workspace smoke test.
pub const CRATE_NAME: &str = "slipstream-core";

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(super::CRATE_NAME, "slipstream-core");
    }
}
```

`slipstream/cli/Cargo.toml`:
```toml
[package]
name = "slipstream-cli"
version = "0.0.1"
edition = "2024"
rust-version = "1.90"
license = "MIT"
publish = false

[[bin]]
name = "slipstream"
path = "src/main.rs"

[dependencies]
slipstream-core = { path = "../core" }
```

`slipstream/cli/src/main.rs`:
```rust
//! Slipstream developer CLI. Real subcommands arrive in Task 0.4.

fn main() {
    println!("{}", slipstream_core::CRATE_NAME);
}
```

- [ ] **Step 4: Run the engine tests**

```bash
cargo test -p slipstream-core -p slipstream-cli
```
Expected: `test tests::smoke ... ok` and overall `test result: ok`.

- [ ] **Step 5: Confirm root package still builds in isolation**

```bash
cargo check
```
Expected: compiles `libzcashlc` (root package only) with no errors.

- [ ] **Step 6: Prove the FFI pipeline (the actual risk)**

```bash
./Scripts/init-local-ffi.sh --macos-only
swift test --filter OfflineTests
./Scripts/reset-local-ffi.sh
```
Expected: script exits 0 and creates `LocalPackages/`; OfflineTests pass against the locally built slice; reset returns the repo to binary-release mode (leave it there — sessions before P4 don't need local FFI).
If the script fails on a cargo invocation: fix by pinning `-p libzcashlc` in the script (additive, marked change), record in Decision Log, re-run.

- [ ] **Step 7: Update STATE.md (T0.2 done, NEXT=T0.3, note script findings) and commit**

```bash
git add Cargo.toml Cargo.lock slipstream/ docs/slipstream/STATE.md
git commit -m "[#N] slipstream: cargo workspace with core+cli crates; FFI pipeline verified"
```

---

### Task 0.3: Domain types in `slipstream-core`

**Files:**
- Create: `slipstream/core/src/config.rs`, `src/error.rs`, `src/events.rs`
- Modify: `slipstream/core/src/lib.rs`, `slipstream/core/Cargo.toml`

- [ ] **Step 1: Add dependencies**

In `slipstream/core/Cargo.toml` under `[dependencies]`:
```toml
thiserror = "2"
tracing = "0.1"
zcash_protocol = "0.9"
```
(Versions match the existing workspace tree; no Decision Log entry needed.)

- [ ] **Step 2: Write the failing tests (in the new modules, code below includes them)**

- [ ] **Step 3: Implement the modules**

`slipstream/core/src/error.rs`:
```rust
//! Crate-wide error type. One variant per subsystem; transport/wallet details
//! become structured payloads as those subsystems land (P1/P2).

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SlipstreamError {
    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("transport: {0}")]
    Transport(String),

    #[error("chain discontinuity at height {at}: {detail}")]
    Discontinuity { at: u32, detail: String },

    #[error("wallet db: {0}")]
    Wallet(String),

    #[error("engine is stopped")]
    Stopped,
}

#[cfg(test)]
mod tests {
    use super::SlipstreamError;

    #[test]
    fn discontinuity_displays_height_and_detail() {
        let e = SlipstreamError::Discontinuity { at: 1_650_000, detail: "prev-hash mismatch".into() };
        assert_eq!(e.to_string(), "chain discontinuity at height 1650000: prev-hash mismatch");
    }
}
```

`slipstream/core/src/config.rs`:
```rust
//! Engine configuration. Defaults are the Sprint-mode values from
//! docs/SLIPSTREAM_DESIGN.md §4; modes adjust them later (P8).

use std::path::PathBuf;

use zcash_protocol::consensus::Network;

use crate::error::SlipstreamError;

/// lightwalletd endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub network: Network,
    /// Path to the (existing, zcash_client_sqlite-managed) wallet database.
    pub wallet_db_path: PathBuf,
    pub endpoint: Endpoint,
    /// Concurrent GetBlockRange sub-streams (P1).
    pub fetch_streams: usize,
    /// Target blocks per in-memory chunk / per scan call (P1/P2).
    pub chunk_blocks: u32,
    /// Upper bound for in-flight downloaded block data.
    pub memory_budget_bytes: usize,
}

impl EngineConfig {
    pub const DEFAULT_FETCH_STREAMS: usize = 4;
    pub const DEFAULT_CHUNK_BLOCKS: u32 = 10_000;
    pub const DEFAULT_MEMORY_BUDGET: usize = 256 * 1024 * 1024;

    pub fn new(network: Network, wallet_db_path: PathBuf, endpoint: Endpoint) -> Self {
        Self {
            network,
            wallet_db_path,
            endpoint,
            fetch_streams: Self::DEFAULT_FETCH_STREAMS,
            chunk_blocks: Self::DEFAULT_CHUNK_BLOCKS,
            memory_budget_bytes: Self::DEFAULT_MEMORY_BUDGET,
        }
    }

    pub fn validate(&self) -> Result<(), SlipstreamError> {
        if self.endpoint.host.is_empty() {
            return Err(SlipstreamError::Config("endpoint host is empty".into()));
        }
        if self.fetch_streams == 0 {
            return Err(SlipstreamError::Config("fetch_streams must be >= 1".into()));
        }
        if self.chunk_blocks < 100 {
            return Err(SlipstreamError::Config("chunk_blocks must be >= 100".into()));
        }
        if self.memory_budget_bytes < 16 * 1024 * 1024 {
            return Err(SlipstreamError::Config("memory_budget_bytes must be >= 16 MiB".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> Endpoint {
        Endpoint { host: "zec.rocks".into(), port: 443, tls: true }
    }

    fn config() -> EngineConfig {
        EngineConfig::new(Network::MainNetwork, PathBuf::from("/tmp/data.db"), endpoint())
    }

    #[test]
    fn defaults_are_valid() {
        assert!(config().validate().is_ok());
    }

    #[test]
    fn zero_streams_rejected() {
        let mut c = config();
        c.fetch_streams = 0;
        assert!(matches!(c.validate(), Err(SlipstreamError::Config(_))));
    }

    #[test]
    fn tiny_chunks_rejected() {
        let mut c = config();
        c.chunk_blocks = 99;
        assert!(matches!(c.validate(), Err(SlipstreamError::Config(_))));
    }
}
```

`slipstream/core/src/events.rs`:
```rust
//! Engine → shell surface: a polled `Snapshot` plus a drained `Event` ring
//! (decision D8 in docs/slipstream/ROADMAP.md). Fields grow in P3; keep
//! both types additive (`#[non_exhaustive]`).

/// Which resource currently bounds throughput (honest-ETA reporting).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bound {
    Download,
    Cpu,
    Commit,
    Idle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncMode {
    /// Foreground restore: all cores, large buffers.
    Sprint,
    /// Foreground catch-up.
    Cruise,
    /// Background slice: minimal footprint, checkpoint-eager.
    Drip,
}

#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct Snapshot {
    pub chain_tip: u32,
    pub fully_scanned_height: u32,
    /// 0.0..=1.0 across the whole wallet recovery window.
    pub coverage: f32,
    pub download_bytes_per_sec: u64,
    pub scan_outputs_per_sec: u64,
    pub bound: Option<Bound>,
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Event {
    Started { mode: SyncMode },
    Progress(Snapshot),
    Finished { fully_scanned_height: u32 },
    Failed { message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_default_is_idle_zeroes() {
        let s = Snapshot::default();
        assert_eq!(s.coverage, 0.0);
        assert_eq!(s.bound, None);
    }
}
```

`slipstream/core/src/lib.rs` (replace placeholder body, keep header comment):
```rust
//! Slipstream sync engine core (platform-neutral).
//! See docs/SLIPSTREAM_DESIGN.md for the architecture and
//! docs/slipstream/ROADMAP.md for the build plan.

pub mod config;
pub mod error;
pub mod events;

pub use config::{EngineConfig, Endpoint};
pub use error::SlipstreamError;
pub use events::{Bound, Event, Snapshot, SyncMode};

/// Crate smoke marker used by the workspace smoke test.
pub const CRATE_NAME: &str = "slipstream-core";

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(super::CRATE_NAME, "slipstream-core");
    }
}
```

- [ ] **Step 4: Run the tests**

```bash
cargo test -p slipstream-core
```
Expected: 6 tests pass (`smoke`, `discontinuity_displays_height_and_detail`, `defaults_are_valid`, `zero_streams_rejected`, `tiny_chunks_rejected`, `snapshot_default_is_idle_zeroes`).

- [ ] **Step 5: Update STATE.md (T0.3 done, NEXT=T0.4) and commit**

```bash
git add slipstream/core docs/slipstream/STATE.md Cargo.lock
git commit -m "[#N] slipstream: core domain types (config, error, events)"
```

---

### Task 0.4: CLI scaffold

**Files:**
- Modify: `slipstream/cli/Cargo.toml`, `slipstream/cli/src/main.rs`

- [ ] **Step 1: Add dependencies**

`slipstream/cli/Cargo.toml` `[dependencies]` becomes:
```toml
slipstream-core = { path = "../core" }
clap = { version = "4", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

- [ ] **Step 2: Implement the scaffold**

`slipstream/cli/src/main.rs`:
```rust
//! Slipstream developer CLI: the primary harness for engine work (decision D5).
//! Subcommands land per phase: `fetch` (P1), `sync` (P2+), `report` (P5).

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "slipstream", version, about = "Slipstream sync engine dev harness")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print engine crate version info.
    Version,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Version => {
            println!("{} {}", slipstream_core::CRATE_NAME, env!("CARGO_PKG_VERSION"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_version_subcommand() {
        let cli = Cli::try_parse_from(["slipstream", "version"]).expect("parses");
        assert!(matches!(cli.cmd, Cmd::Version));
    }

    #[test]
    fn rejects_unknown_subcommand() {
        assert!(Cli::try_parse_from(["slipstream", "warp"]).is_err());
    }
}
```

- [ ] **Step 3: Run tests + smoke the binary**

```bash
cargo test -p slipstream-cli
cargo run -p slipstream-cli -- version
```
Expected: 2 tests pass; binary prints `slipstream-core 0.0.1`.

- [ ] **Step 4: Update STATE.md (T0.4 done, NEXT=T0.5) and commit**

```bash
git add slipstream/cli docs/slipstream/STATE.md Cargo.lock
git commit -m "[#N] slipstream: CLI scaffold with version subcommand"
```

---

### Task 0.5: CLAUDE.md pointer + gate G0

**Files:**
- Modify: `CLAUDE.md`
- Modify: `docs/slipstream/STATE.md`

- [ ] **Step 1: Append to `CLAUDE.md` (end of file)**

```markdown
## Slipstream (next-gen sync engine prototype)

Active multi-session project building a new Rust sync engine under `slipstream/` (branch `slipstream`).
For any Slipstream / sync-engine work: read `docs/slipstream/STATE.md` FIRST (current status + next task),
then `docs/slipstream/CONVENTIONS.md` (session protocol + always-green commands).
The old SDK sync path is frozen for this work — additive changes only.
```

- [ ] **Step 2: Run gate G0 in full**

```bash
cargo test -p slipstream-core -p slipstream-cli   # expect: all green
cargo check                                        # root package builds
swift test --filter OfflineTests                   # old SDK untouched (binary mode)
```
Expected: everything green. (The FFI script was already proven in T0.2 Step 6.)

- [ ] **Step 3: Record G0 in STATE.md**

Mark gate G0 ☑ with date + command outputs summary; T0.5 done; set NEXT ACTION to **T1.0 — write detailed Phase 1 plan** (`docs/slipstream/plans/<date>-phase-1-transport.md`); append session-log line.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md docs/slipstream/STATE.md
git commit -m "[#N] slipstream: CLAUDE.md pointer; gate G0 green"
```

---

## Phase exit criteria (G0)

- [ ] `slipstream` branch exists with tracking issue `#N` recorded in STATE.md.
- [ ] `cargo test -p slipstream-core -p slipstream-cli` green.
- [ ] `./Scripts/init-local-ffi.sh --macos-only` + OfflineTests proven on the workspace (T0.2), repo left in binary-release mode.
- [ ] CLAUDE.md points future sessions at STATE.md.
- [ ] STATE.md NEXT ACTION = T1.0.
