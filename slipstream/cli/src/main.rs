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
    /// Fetch a block range into memory and report throughput (G1 benchmark).
    Fetch {
        /// lightwalletd URL, e.g. https://zec.rocks:443 or http://127.0.0.1:9067
        #[arg(long)]
        server: String,
        /// Inclusive range, e.g. 2500000..2600000 (start..end)
        #[arg(long)]
        range: String,
        /// Parallel streams for the measured run.
        #[arg(long, default_value_t = 4, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
        streams: usize,
        /// Blocks per chunk.
        #[arg(long, default_value_t = 10_000)]
        chunk: u32,
        /// Also run a K=1 baseline first (required for the G1 ratio).
        #[arg(long, default_value_t = true)]
        baseline: bool,
    },
    /// Full sync pass into a wallet database (creates it if absent).
    Sync {
        /// lightwalletd URL, e.g. https://zec.rocks:443 or http://127.0.0.1:9067
        #[arg(long)]
        server: String,
        /// Wallet directory (data.db lives inside).
        #[arg(long)]
        wallet_dir: std::path::PathBuf,
        /// UFVK to import on first run (required for a fresh wallet).
        #[arg(long)]
        ufvk: Option<String>,
        /// Birthday height for --ufvk import.
        #[arg(long)]
        birthday: Option<u64>,
        /// Parallel fetch streams.
        #[arg(long, default_value_t = 4, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
        streams: usize,
        /// Blocks per chunk.
        #[arg(long, default_value_t = 10_000)]
        chunk: u32,
        /// Use sparse in-memory commitment-tree persistence (P6, default on).
        /// Pass `--sparse false` to disable (kill switch — reverts to upstream path).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        sparse: bool,
        /// Byte budget per fetch sub-chunk (T6.8-S adaptive split; makes dense
        /// "sandblasting" eras traversable). Must be >= 1 MiB.
        #[arg(long, default_value_t = slipstream_core::EngineConfig::DEFAULT_CHUNK_SPLIT_BYTES)]
        chunk_split_bytes: usize,
        /// T8.4: in-memory fetch/decode budget (bytes); must be >= 16 MiB. Lower it for
        /// memory-constrained runs — the device path derates this automatically from
        /// ProcessInfo.physicalMemory; this flag is the Mac/CLI equivalent (book ch.19).
        #[arg(long, default_value_t = slipstream_core::EngineConfig::DEFAULT_MEMORY_BUDGET)]
        memory_budget_bytes: usize,
        /// T6.9: depth-1 write-behind persistence pipelining (overlap chunk N's
        /// DB commit with chunk N+1's decryption). Requires sparse. Default ON
        /// since the 2026-06-12 flip; `--write-behind false` is the kill switch.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
        write_behind: bool,
        /// B0 (Phase B): compute Orchard subtree combines on the GPU (requires sparse and a
        /// build with `--features gpu`). Default off; CPU path identical when off.
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
        gpu_subtree: bool,
        /// Persist-pipelining: write-behind queue depth (max unpersisted units before scan
        /// blocks). 1 = legacy depth-1; higher hides more persist behind scan (~22% on modern
        /// devices) at the cost of RAM. The committed data.db is identical at any depth.
        #[arg(long, default_value_t = 1, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=64))]
        persist_depth: usize,
        /// T8.1: after reaching tip, keep the wallet tracking the chain.
        /// Probes the tip every 10–30 s (jittered); runs a full pass whenever a
        /// new block arrives. Cancellable with Ctrl-C. Useful for Mac CLI validation
        /// and for observing follow behaviour without a full Zodl build.
        #[arg(long, default_value_t = false)]
        follow: bool,
    },
    /// v0.4 P0 bench (spec §3.3): scripted fresh-restore benchmark. Restores the
    /// given UFVK into an EMPTY wallet dir (temp by default — a bench is always a
    /// fresh restore) and prints the engine's end-of-pass BenchSummary: stage
    /// split + shard census + the Plan-A graftable prediction, also written as
    /// JSON (the artifact bench-ios shares).
    Bench {
        /// lightwalletd URL, e.g. https://zec.rocks:443
        #[arg(long)]
        server: String,
        /// UFVK of the reference wallet to restore.
        #[arg(long)]
        ufvk: String,
        /// Birthday height for the restore.
        #[arg(long)]
        birthday: u64,
        /// Wallet directory (must NOT already contain a data.db). Default: temp dir.
        #[arg(long)]
        wallet_dir: Option<std::path::PathBuf>,
        /// v0.4 Plan A graft lever: skip building note-free completed shards by
        /// installing server roots (the A/B switch for the bet legs).
        /// DEFAULT ON since v0.4.0 (P3 gates passed) — pass `--graft false` for a baseline run.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
        graft: bool,
        /// Banked B0 GPU offload lever (requires a `--features gpu` build).
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
        gpu_subtree: bool,
        /// v0.4 Plan B lever: batch-affine Orchard combine (the SIMD bet leg).
        /// DEFAULT ON since v0.4.0 — pass `--batch-combine false` for a baseline run.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
        batch_combine: bool,
        /// v0.5 C1 lever: batched same-scalar trial-decrypt DH (forked orchard
        /// lockstep kernel). Default OFF until the C3 device gates.
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
        batch_decrypt: bool,
        /// v0.5 scan-pacer lever: derive chunk-boundary treestates locally
        /// (one seed fetch per range instead of one GetTreeState round-trip
        /// per boundary — P1 measured those at 62% of the Mac scan wall).
        /// Default OFF until the A/B + audit gates.
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
        local_treestate: bool,
        /// Boundary-audit cadence for --local-treestate: every Nth local
        /// boundary also fetches the server treestate OFF the critical path
        /// and compares (0 = off, 1 = audit EVERY boundary). Default 1.
        #[arg(long, default_value_t = 1)]
        treestate_verify_sample: u32,
        /// Task 10 audit cadence: build-and-verify every Nth graftable shard
        /// against the server root (0 = off, 1 = audit EVERY graft — the
        /// validation mode). Default matches the engine (16).
        #[arg(long, default_value_t = 16)]
        graft_verify_sample: u32,
        /// Write the BenchSummary JSON here (default: <wallet_dir>/bench.json).
        #[arg(long)]
        json: Option<std::path::PathBuf>,
        /// Keep the wallet dir afterwards (temp dirs are deleted by default).
        #[arg(long, default_value_t = false)]
        keep: bool,
    },
    /// [API v2 Phase C acceptance] Live wallet console rendered ONLY from the v2 contract:
    /// the derived engine snapshot (state/permille/recovering/stalled), the engine-owned SQL
    /// views (`slipstream_v_recovery_balance`, `slipstream_v_tx_reconciled`), and the two
    /// DOCUMENTED one-line host rules (balance = recovering ? view : upstream summary;
    /// visible = reconciled OR NOT recovering). ZERO wallet math lives in this command — if
    /// it ever needs any, the engine API is wrong and must grow instead (ENGINE_API_V2.md §8).
    Watch {
        /// lightwalletd URL, e.g. https://zec.rocks:443
        #[arg(long)]
        server: String,
        /// Wallet directory (data.db lives inside).
        #[arg(long)]
        wallet_dir: std::path::PathBuf,
        /// UFVK to import on first run (fresh restore demo).
        #[arg(long)]
        ufvk: Option<String>,
        /// Birthday height for --ufvk import.
        #[arg(long)]
        birthday: Option<u64>,
        /// Render interval in milliseconds (min 200).
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
    },
    /// Golden-oracle run: sync the same UFVK/birthday twice into two wallet dirs
    /// (A = upstream persistence, B = upstream until T6.3 lands --sparse-b),
    /// then semantically diff the resulting data.db files. Exit 0 = identical.
    Oracle {
        #[arg(long)]
        server: String,
        /// Wallet dir A (created; must not contain data.db).
        #[arg(long)]
        wallet_a: std::path::PathBuf,
        /// Wallet dir B (created; must not contain data.db).
        #[arg(long)]
        wallet_b: std::path::PathBuf,
        #[arg(long)]
        ufvk: String,
        #[arg(long)]
        birthday: u64,
        /// Run B with sparse persistence (T6.3+).
        #[arg(long, default_value_t = false)]
        sparse_b: bool,
        /// T6.9: run B with write-behind pipelining as well (requires --sparse-b).
        #[arg(long, default_value_t = false)]
        write_behind_b: bool,
        /// B0 (Phase B): run B with the GPU Orchard subtree build (requires --sparse-b and a
        /// build with `--features gpu`). The acceptance gate: oracle VERDICT IDENTICAL.
        #[arg(long, default_value_t = false)]
        gpu_subtree_b: bool,
        /// Run B with a deeper write-behind queue (persist-pipelining). 1 = depth-1. The oracle
        /// proves any depth is byte-identical (VERDICT IDENTICAL vs the upstream run A).
        #[arg(long, default_value_t = 1, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..=64))]
        persist_depth_b: usize,
        #[arg(long, default_value_t = 4, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
        streams: usize,
        #[arg(long, default_value_t = 10_000)]
        chunk: u32,
    },
}

fn parse_server(s: &str) -> Result<slipstream_core::Endpoint, String> {
    let (tls, rest) = if let Some(r) = s.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = s.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!("server must start with http:// or https://: {s}"));
    };
    let (host, port) = rest
        .trim_end_matches('/')
        .split_once(':')
        .ok_or_else(|| format!("server must include a port: {s}"))?;
    Ok(slipstream_core::Endpoint {
        host: host.to_string(),
        port: port.parse().map_err(|e| format!("bad port: {e}"))?,
        tls,
    })
}

fn parse_range(s: &str) -> Result<(u64, u64), String> {
    if s.contains("..=") {
        return Err(format!("range must be start..end (not ..=): {s}"));
    }
    let (a, b) = s.split_once("..").ok_or_else(|| format!("range must be start..end: {s}"))?;
    let start: u64 = a.trim().parse().map_err(|e| format!("bad start: {e}"))?;
    let end: u64 = b.trim().parse().map_err(|e| format!("bad end: {e}"))?;
    if end < start {
        return Err("range end must be >= start".into());
    }
    Ok((start, end))
}

async fn run_fetch_bench(
    endpoint: &slipstream_core::Endpoint,
    start: u64,
    end: u64,
    chunk: u32,
    streams: usize,
) -> Result<slipstream_core::fetch::FetchStats, slipstream_core::SlipstreamError> {
    let (tx, mut rx) = slipstream_core::chunk::chunk_queue(256 * 1024 * 1024);
    let drain = tokio::spawn(async move { while let Some((_c, _p, _b)) = rx.recv().await {} });
    let plan = slipstream_core::fetch::FetchPlan::new(start, end, chunk, streams);
    let stats = slipstream_core::fetch::run_fetch(endpoint, plan, tx, None).await?;
    let _ = drain.await;
    Ok(stats)
}

fn cmd_fetch(server: String, range: String, streams: usize, chunk: u32, baseline: bool) {
    let endpoint = parse_server(&server).unwrap_or_else(|e| { eprintln!("{e}"); std::process::exit(2) });
    let (start, end) = parse_range(&range).unwrap_or_else(|e| { eprintln!("{e}"); std::process::exit(2) });
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let mut base_stats = None;
        if baseline {
            println!("baseline run (streams=1)...");
            match run_fetch_bench(&endpoint, start, end, chunk, 1).await {
                Ok(s) => {
                    println!(
                        "  K=1: {} blocks, {:.1} MB, {:.1}s, {:.0} blk/s, {:.2} MB/s",
                        s.blocks, s.bytes as f64 / 1048576.0, s.elapsed.as_secs_f64(),
                        s.blocks_per_sec(), s.megabytes_per_sec()
                    );
                    base_stats = Some(s);
                }
                Err(e) => { eprintln!("baseline failed: {e}"); std::process::exit(1) }
            }
        }
        println!("measured run (streams={streams})...");
        match run_fetch_bench(&endpoint, start, end, chunk, streams).await {
            Ok(s) => {
                println!(
                    "  K={streams}: {} blocks, {:.1} MB, {:.1}s, {:.0} blk/s, {:.2} MB/s",
                    s.blocks, s.bytes as f64 / 1048576.0, s.elapsed.as_secs_f64(),
                    s.blocks_per_sec(), s.megabytes_per_sec()
                );
                if let Some(b) = base_stats {
                    println!("  speedup vs K=1: {:.2}x", s.megabytes_per_sec() / b.megabytes_per_sec());
                }
            }
            Err(e) => { eprintln!("fetch failed: {e}"); std::process::exit(1) }
        }
    });
}

/// Validate sync argument combinations. Extracted as a pure function to stay testable
/// without any I/O or network — specifically validates that a UFVK is not supplied
/// without a birthday height.
///
/// Returns `Ok(Some((ufvk_str, birthday)))` if both are present, `Ok(None)` if neither,
/// and `Err(String)` if the combination is invalid.
// ── `watch` (API v2 Phase C acceptance) ────────────────────────────────────────────────────

fn event_tag_name(tag: u8) -> &'static str {
    match tag {
        1 => "SyncStarted",
        2 => "SyncProgress",
        3 => "SyncDone",
        4 => "SyncError",
        5 => "FoundTransactions",
        _ => "Unknown",
    }
}

/// Display formatting only (integer split — no wallet math).
fn zec_display(zat: i64) -> String {
    let sign = if zat < 0 { "-" } else { "" };
    let a = zat.unsigned_abs();
    format!("{sign}{}.{:08}", a / 100_000_000, a % 100_000_000)
}

fn uuid_prefix(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// The Phase C acceptance harness: renders wallet state ONLY from the v2 contract.
/// If this function ever needs wallet math, the engine API is wrong (ENGINE_API_V2.md §8).
fn cmd_watch(
    server: String,
    wallet_dir: std::path::PathBuf,
    ufvk: Option<String>,
    birthday: Option<u64>,
    interval_ms: u64,
) {
    let endpoint = parse_server(&server).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    });
    let ufvk_arg = validate_sync_args(ufvk.as_deref(), birthday).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(2)
    });
    let db_path = wallet_dir.join("data.db");
    let cfg = slipstream_core::EngineConfig::new(
        slipstream_core::Network::MainNetwork,
        db_path.clone(),
        endpoint,
    );

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        let reporter = slipstream_core::SessionReporter {
            progress: std::sync::Arc::new(slipstream_core::Progress::default()),
            state: std::sync::Arc::new(std::sync::Mutex::new(
                slipstream_core::ffi_handle::SyncState::Idle,
            )),
            events: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        // [API v2.1 E-3] Truthful-from-open: seed the snapshot atomics from the persisted
        // wallet (same call the iOS FFI open() makes) — the SECOND-HOST acceptance proof
        // that no host needs pre-first-suggest compensation. Failure = cold snapshot.
        if let Ok(session) =
            slipstream_core::wallet_session::WalletSession::open(slipstream_core::Network::MainNetwork, &db_path)
        {
            if let Err(e) =
                slipstream_core::scheduler::seed_progress_from_wallet(&reporter.progress, &session)
            {
                eprintln!("warn: E-3 open-time snapshot seed failed ({e}) — starting cold");
            }
        }
        let scfg = slipstream_core::SessionConfig {
            engine: cfg,
            account: ufvk_arg.map(|(s, h)| (s.to_string(), h)),
            tor: None,
        };
        let session = tokio::spawn(slipstream_core::session::run_session(
            scfg,
            reporter.clone(),
            std::sync::Arc::new(tokio::sync::Mutex::new(())),
        ));

        println!("watch: rendering from the v2 contract only (derived snapshot + engine views). Ctrl-C to stop.");
        let mut interval =
            tokio::time::interval(std::time::Duration::from_millis(interval_ms.max(200)));
        loop {
            interval.tick().await;

            // v2 channel 1: the derived snapshot — the SAME derivation the FFI serves
            // (fail-safe recovery latch, monotonic permille, stall clock included).
            let state = *reporter.state.lock().unwrap_or_else(|p| p.into_inner());
            let snap = slipstream_core::ffi_handle::derive_snapshot(&reporter.progress, state);

            // Edge signals: drain + print.
            let drained: Vec<slipstream_core::ffi_handle::FfiSlipstreamEvent> = {
                let mut ring = reporter.events.lock().unwrap_or_else(|p| p.into_inner());
                std::mem::take(&mut *ring)
            };
            for e in &drained {
                println!("event: {} (value {})", event_tag_name(e.tag), e.value);
            }

            // v2 channel 2 — the DOCUMENTED host rules, verbatim:
            //   balance = is_recovering ? SELECT slipstream_v_recovery_balance : upstream summary
            let balances: Vec<(String, i64, &'static str)> = if snap.is_recovering == 1 {
                let mut out = Vec::new();
                if let Ok(conn) = rusqlite::Connection::open(&db_path) {
                    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
                    if let Ok(mut stmt) = conn
                        .prepare("SELECT account_uuid, balance_zat FROM slipstream_v_recovery_balance")
                    {
                        if let Ok(rows) = stmt.query_map([], |r| {
                            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?))
                        }) {
                            for row in rows.flatten() {
                                out.push((uuid_prefix(&row.0), row.1, "Σ reconciled (recovering)"));
                            }
                        }
                    }
                }
                out
            } else {
                use zcash_client_backend::data_api::WalletRead;
                match zcash_client_sqlite::WalletDb::for_path(
                    &db_path,
                    zcash_protocol::consensus::Network::MainNetwork,
                    zcash_client_sqlite::util::SystemClock,
                    rand::rngs::OsRng,
                ) {
                    Ok(db) => match db.get_wallet_summary(
                        zcash_client_backend::data_api::wallet::ConfirmationsPolicy::default(),
                    ) {
                        Ok(Some(summary)) => summary
                            .account_balances()
                            .iter()
                            .map(|(uuid, b)| {
                                (
                                    uuid_prefix(uuid.expose_uuid().as_bytes()),
                                    i64::try_from(u64::from(b.total())).unwrap_or(i64::MAX),
                                    "upstream summary",
                                )
                            })
                            .collect(),
                        _ => Vec::new(),
                    },
                    Err(_) => Vec::new(),
                }
            };

            //   visible = reconciled OR NOT is_recovering (mined txs only)
            let visible: i64 = rusqlite::Connection::open(&db_path)
                .ok()
                .and_then(|conn| {
                    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
                    let sql = if snap.is_recovering == 1 {
                        "SELECT COUNT(*) FROM transactions t WHERE t.mined_height IS NOT NULL \
                         AND NOT EXISTS (SELECT 1 FROM slipstream_v_tx_reconciled r \
                                         WHERE r.txid = t.txid AND r.reconciled = 0)"
                    } else {
                        "SELECT COUNT(*) FROM transactions t WHERE t.mined_height IS NOT NULL"
                    };
                    conn.query_row(sql, [], |r| r.get(0)).ok()
                })
                .unwrap_or(-1);

            let state_name = match snap.state {
                0 => "idle",
                1 => "syncing",
                2 => "error",
                3 => "done",
                _ => "?",
            };
            let bal_str = if balances.is_empty() {
                "balance: (none yet)".to_string()
            } else {
                balances
                    .iter()
                    .map(|(u, z, src)| format!("{u}: {} ZEC [{src}]", zec_display(*z)))
                    .collect::<Vec<_>>()
                    .join(" | ")
            };
            println!(
                "[{state_name}] {}‰ | recovering: {} | stalled: {}s | scanned {}/{} | tip {} | visible txs: {} | {}",
                snap.progress_permille,
                snap.is_recovering == 1,
                snap.stalled_seconds,
                snap.scanned_blocks,
                snap.pass_total_blocks,
                snap.chain_tip,
                visible,
                bal_str
            );

            if session.is_finished() {
                eprintln!("watch: session ended (non-transient initial error) — see logs above");
                std::process::exit(1);
            }
        }
    });
}

fn validate_sync_args(
    ufvk: Option<&str>,
    birthday: Option<u64>,
) -> Result<Option<(&str, u64)>, String> {
    match (ufvk, birthday) {
        (Some(u), Some(b)) => Ok(Some((u, b))),
        (None, None) => Ok(None),
        (Some(_), None) => {
            Err("--ufvk requires --birthday: provide the wallet birthday height".into())
        }
        (None, Some(_)) => {
            // birthday without ufvk is silently ignored (may be used with an existing wallet)
            Ok(None)
        }
    }
}

/// Guard: `--gpu-subtree[-b]` is meaningless unless the binary was built with
/// `--features gpu`. Without it the GPU routing falls back to the CPU path — which for
/// the oracle would be a FALSE `VERDICT IDENTICAL`. Fail loudly instead of silently.
fn require_gpu_feature_if(requested: bool, flag: &str) {
    if requested && !cfg!(feature = "gpu") {
        eprintln!(
            "error: {flag} needs a build with --features gpu (else it silently runs the CPU \
             path — a false IDENTICAL). Rebuild, e.g.: cargo run -p slipstream-cli --features gpu -- …"
        );
        std::process::exit(2);
    }
}

/// v0.4 P0 (spec §3.3): fresh-restore benchmark. One measured pass, honest by
/// construction: refuses a pre-populated wallet dir (that would be a catch-up,
/// not a restore) and prints/persists the engine-written BenchSummary.
#[allow(clippy::too_many_arguments)]
fn cmd_bench(
    server: String,
    ufvk: String,
    birthday: u64,
    wallet_dir: Option<std::path::PathBuf>,
    graft: bool,
    gpu_subtree: bool,
    batch_combine: bool,
    batch_decrypt: bool,
    local_treestate: bool,
    treestate_verify_sample: u32,
    graft_verify_sample: u32,
    json: Option<std::path::PathBuf>,
    keep: bool,
) {
    let endpoint = parse_server(&server).unwrap_or_else(|e| { eprintln!("{e}"); std::process::exit(2) });
    require_gpu_feature_if(gpu_subtree, "--gpu-subtree");

    // Wallet dir: user-supplied (must be fresh) or a temp dir (deleted unless --keep).
    let (dir, tempdir_guard) = match wallet_dir {
        Some(d) => {
            if d.join("data.db").exists() {
                eprintln!(
                    "error: {} already contains a data.db — a bench is a FRESH restore; \
                     point --wallet-dir at an empty dir or omit it for a temp dir",
                    d.display()
                );
                std::process::exit(2);
            }
            std::fs::create_dir_all(&d)
                .unwrap_or_else(|e| { eprintln!("error: create {}: {e}", d.display()); std::process::exit(2) });
            (d, None)
        }
        None => {
            let td = tempfile::tempdir()
                .unwrap_or_else(|e| { eprintln!("error: tempdir: {e}"); std::process::exit(2) });
            (td.path().to_path_buf(), Some(td))
        }
    };

    let json_path = json.unwrap_or_else(|| dir.join("bench.json"));
    let mut cfg = slipstream_core::EngineConfig::new(
        slipstream_core::Network::MainNetwork,
        dir.join("data.db"),
        endpoint,
    );
    cfg.gpu_subtree = gpu_subtree;
    // v0.4 Plan A lever (Task 8+): live A/B switch — the whole point of bench.
    cfg.graft_subtree = graft;
    cfg.batch_decrypt = batch_decrypt;
    cfg.local_treestate = local_treestate;
    cfg.treestate_verify_sample = treestate_verify_sample;
    cfg.graft_verify_sample = graft_verify_sample;
    cfg.batch_combine = batch_combine;
    cfg.bench_json_path = Some(json_path.clone());

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let outcome = rt.block_on(async {
        let progress = std::sync::Arc::new(slipstream_core::Progress::default());
        let ticker_progress = std::sync::Arc::clone(&progress);
        let ticker = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
            interval.tick().await;
            loop {
                interval.tick().await;
                println!(
                    "progress: fetched {} | scanned {} | enhanced {} (tip {})",
                    ticker_progress.fetched(),
                    ticker_progress.scanned(),
                    ticker_progress.enhanced(),
                    ticker_progress.chain_tip()
                );
            }
        });
        let result = slipstream_core::engine::sync_once(
            &cfg,
            Some((ufvk.as_str(), birthday)),
            Some(progress),
            None,
        )
        .await;
        ticker.abort();
        result
    });

    let outcome = outcome.unwrap_or_else(|e| { eprintln!("bench failed: {e}"); std::process::exit(1) });

    // Human table — same numbers the engine wrote to the JSON artifact.
    let r = &outcome.report;
    let wait_s = r.persist_wait_elapsed.as_secs_f64();
    let busy_s = r.persist_busy_elapsed.as_secs_f64();
    println!();
    println!(
        "bench: total {:.1}s | fetch {:.1}s | scan {:.1}s | enhance {:.1}s | persist_wait {:.1}s | overlap {:.1}s",
        outcome.elapsed.as_secs_f64(),
        r.fetch_elapsed.as_secs_f64(),
        r.scan_elapsed.as_secs_f64(),
        outcome.enhance_elapsed.as_secs_f64(),
        wait_s,
        (busy_s - wait_s).max(0.0),
    );
    for (label, c) in [("sapling", &r.census_sapling), ("orchard", &r.census_orchard)] {
        println!(
            "census {label}: shards {} | noted {} | graftable {:.0}%",
            c.shards(),
            c.noted_shards(),
            c.graftable_fraction() * 100.0
        );
    }
    println!(
        "Plan A ceiling (orchard, the dominant combine cost): skip ~{:.0}% of shard builds on this wallet",
        r.census_orchard.graftable_fraction() * 100.0
    );
    if json_path.exists() {
        println!("json: {}", json_path.display());
    } else {
        eprintln!("warning: engine did not write the bench JSON at {}", json_path.display());
    }
    match (tempdir_guard, keep) {
        (Some(td), true) => {
            // Leak deliberately: --keep promotes the temp dir to a kept artifact.
            let path = td.keep();
            println!("wallet dir kept: {}", path.display());
        }
        (Some(_td), false) => {} // dropped → deleted
        (None, _) => println!("wallet dir: {}", dir.display()),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_sync(
    server: String,
    wallet_dir: std::path::PathBuf,
    ufvk: Option<String>,
    birthday: Option<u64>,
    streams: usize,
    chunk: u32,
    sparse: bool,
    chunk_split_bytes: usize,
    memory_budget_bytes: usize,
    write_behind: bool,
    gpu_subtree: bool,
    persist_depth: usize,
    follow: bool,
) {
    let endpoint = parse_server(&server).unwrap_or_else(|e| { eprintln!("{e}"); std::process::exit(2) });

    if ufvk.is_none() && birthday.is_some() {
        eprintln!("note: --birthday without --ufvk is ignored (no import will occur)");
    }

    let ufvk_arg = validate_sync_args(ufvk.as_deref(), birthday)
        .unwrap_or_else(|e| { eprintln!("error: {e}"); std::process::exit(2) });

    let mut cfg = slipstream_core::EngineConfig::new(
        slipstream_core::Network::MainNetwork,
        wallet_dir.join("data.db"),
        endpoint,
    );
    cfg.fetch_streams = streams;
    cfg.chunk_blocks = chunk;
    cfg.sparse_persistence = sparse;
    cfg.chunk_split_bytes = chunk_split_bytes;
    cfg.memory_budget_bytes = memory_budget_bytes;
    require_gpu_feature_if(gpu_subtree, "--gpu-subtree");
    // `--sparse false` (the sparse kill switch) implies write-behind off: the
    // deferred commit runs the sparse put_blocks path, so it cannot outlive it.
    cfg.write_behind = write_behind && sparse;
    cfg.gpu_subtree = gpu_subtree && sparse;
    cfg.persist_depth = persist_depth;

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        // Build shared progress state for the CLI ticker (decision D8 poll-based).
        let progress = std::sync::Arc::new(slipstream_core::Progress::default());
        let ticker_progress = std::sync::Arc::clone(&progress);

        // Spawn a 2-second ticker task that prints one line per tick.
        // Plain println lines (no \r tricks — some terminals do not support them).
        // The task is aborted (not joined) after sync_once returns.
        let ticker = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                let fetched = ticker_progress.fetched();
                let scanned = ticker_progress.scanned();
                let enhanced = ticker_progress.enhanced();
                let tip = ticker_progress.chain_tip();
                println!(
                    "progress: fetched {} | scanned {} | enhanced {} (tip {})",
                    fetched, scanned, enhanced, tip
                );
            }
        });

        // --follow: run the FULL autonomous engine session (import if --ufvk, resilient initial
        // pass, then tip-following + mempool) via slipstream_core::session::run_session — the
        // SAME orchestration the FFI uses. Observability = the ticker above + the engine's own
        // tracing (the "sync stage split" lines). Runs until Ctrl-C; returns only on a
        // non-transient initial error. Replaces the old bespoke loop (which exited on any
        // follow-pass blip — the exact resilience hazard the lift removes).
        if follow {
            let scfg = slipstream_core::SessionConfig {
                engine: cfg.clone(),
                account: ufvk_arg.map(|(s, h)| (s.to_string(), h)),
                tor: None,
            };
            let reporter = slipstream_core::SessionReporter {
                progress: std::sync::Arc::clone(&progress),
                state: std::sync::Arc::new(std::sync::Mutex::new(
                    slipstream_core::ffi_handle::SyncState::Done,
                )),
                events: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            };
            println!("follow: running autonomous engine session (Ctrl-C to stop) ...");
            slipstream_core::session::run_session(
                scfg,
                reporter,
                std::sync::Arc::new(tokio::sync::Mutex::new(())),
            )
            .await;
            ticker.abort();
            eprintln!("sync session ended: non-transient initial error (see logs above)");
            std::process::exit(1);
        }

        let result = slipstream_core::engine::sync_once(&cfg, ufvk_arg, Some(progress), None).await;

        // Abort the ticker (JoinHandle::abort is fine per spec — no cleanup needed).
        ticker.abort();

        match result {
            Ok(outcome) => {
                let mb = outcome.report.fetch.bytes as f64 / 1_048_576.0;
                println!(
                    "synced to tip {} in {:.1}s",
                    outcome.chain_tip,
                    outcome.elapsed.as_secs_f64()
                );
                println!(
                    "ranges {} | fetched {} blocks ({:.1} MB) | scanned {} blocks",
                    outcome.report.ranges_processed,
                    outcome.report.fetch.blocks,
                    mb,
                    outcome.report.scan.blocks,
                );
                println!(
                    "notes found: sapling {} orchard {}",
                    outcome.report.scan.sapling_received,
                    outcome.report.scan.orchard_received,
                );
                println!(
                    "enhanced: {} txs, {} statuses ({} skipped)",
                    outcome.enhance.txs_stored,
                    outcome.enhance.statuses_set,
                    outcome.enhance.skipped,
                );
                println!(
                    "utxos: {} across {} accounts",
                    outcome.transparent.utxos,
                    outcome.transparent.accounts,
                );
                // Per-stage timing + bound (Decision-Log requirement for honest G5 reporting).
                println!(
                    "stages: fetch {:.1}s | scan {:.1}s | enhance {:.1}s (bound: {})",
                    outcome.report.fetch_elapsed.as_secs_f64(),
                    outcome.report.scan_elapsed.as_secs_f64(),
                    outcome.enhance_elapsed.as_secs_f64(),
                    outcome.bound(),
                );
                // T6.9 write-behind overlap quality (only printed when active).
                let pw = outcome.report.persist_wait_elapsed.as_secs_f64();
                let pb = outcome.report.persist_busy_elapsed.as_secs_f64();
                if pb > 0.0 {
                    println!(
                        "write-behind: persist busy {:.1}s | wait {:.1}s | overlap won {:.1}s",
                        pb,
                        pw,
                        (pb - pw).max(0.0),
                    );
                }
                // Reorg summary (only if any recoveries occurred).
                if outcome.report.reorgs_recovered > 0 {
                    println!("reorgs: {} recovered", outcome.report.reorgs_recovered);
                }

            }
            Err(e) => {
                eprintln!("sync failed: {e}");
                std::process::exit(1);
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn cmd_oracle(
    server: String,
    wallet_a: std::path::PathBuf,
    wallet_b: std::path::PathBuf,
    ufvk: String,
    birthday: u64,
    sparse_b: bool,
    write_behind_b: bool,
    gpu_subtree_b: bool,
    persist_depth_b: usize,
    streams: usize,
    chunk: u32,
) {
    let endpoint = parse_server(&server).unwrap_or_else(|e| { eprintln!("{e}"); std::process::exit(2) });
    if write_behind_b && !sparse_b {
        eprintln!("error: --write-behind-b requires --sparse-b");
        std::process::exit(2);
    }
    if gpu_subtree_b && !sparse_b {
        eprintln!("error: --gpu-subtree-b requires --sparse-b");
        std::process::exit(2);
    }
    require_gpu_feature_if(gpu_subtree_b, "--gpu-subtree-b");
    for d in [&wallet_a, &wallet_b] {
        if d.join("data.db").exists() {
            eprintln!("error: {} already contains data.db — oracle needs fresh wallets", d.display());
            std::process::exit(2);
        }
    }
    let mk_cfg = |dir: &std::path::Path, sparse: bool, write_behind: bool, gpu_subtree: bool, persist_depth: usize| {
        let mut cfg = slipstream_core::EngineConfig::new(
            slipstream_core::Network::MainNetwork,
            dir.join("data.db"),
            endpoint.clone(),
        );
        cfg.fetch_streams = streams;
        cfg.chunk_blocks = chunk;
        cfg.sparse_persistence = sparse;
        cfg.write_behind = write_behind;
        cfg.gpu_subtree = gpu_subtree;
        cfg.persist_depth = persist_depth;
        cfg
    };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let verdict = rt.block_on(async {
        println!("oracle: run A (upstream persistence) …");
        let a = slipstream_core::engine::sync_once(&mk_cfg(&wallet_a, false, false, false, 1), Some((ufvk.as_str(), birthday)), None, None).await?;
        println!("oracle: run A done — tip {} in {:.1?}", a.chain_tip, a.elapsed);
        println!("oracle: run B (sparse_b={sparse_b} write_behind_b={write_behind_b} gpu_subtree_b={gpu_subtree_b} persist_depth_b={persist_depth_b}) …");
        let b = slipstream_core::engine::sync_once(&mk_cfg(&wallet_b, sparse_b, write_behind_b, gpu_subtree_b, persist_depth_b), Some((ufvk.as_str(), birthday)), None, None).await?;
        println!("oracle: run B done — tip {} in {:.1?}", b.chain_tip, b.elapsed);
        if a.chain_tip != b.chain_tip {
            eprintln!("oracle: TIP SKEW (A={} B={}) — rerun when the chain is quiet", a.chain_tip, b.chain_tip);
            std::process::exit(3);
        }
        slipstream_core::oracle::semantic_diff(&wallet_a.join("data.db"), &wallet_b.join("data.db"))
    });
    match verdict {
        Ok(report) => {
            print!("{}", report.render());
            if report.is_clean() {
                println!("oracle: VERDICT IDENTICAL");
            } else {
                println!("oracle: VERDICT DIVERGED");
                std::process::exit(1);
            }
        }
        Err(e) => { eprintln!("oracle failed: {e}"); std::process::exit(1); }
    }
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
        Cmd::Fetch { server, range, streams, chunk, baseline } => {
            cmd_fetch(server, range, streams, chunk, baseline);
        }
        Cmd::Sync { server, wallet_dir, ufvk, birthday, streams, chunk, sparse, chunk_split_bytes, memory_budget_bytes, write_behind, gpu_subtree, persist_depth, follow } => {
            cmd_sync(server, wallet_dir, ufvk, birthday, streams, chunk, sparse, chunk_split_bytes, memory_budget_bytes, write_behind, gpu_subtree, persist_depth, follow);
        }
        Cmd::Bench { server, ufvk, birthday, wallet_dir, graft, gpu_subtree, batch_combine, batch_decrypt, local_treestate, treestate_verify_sample, graft_verify_sample, json, keep } => {
            cmd_bench(server, ufvk, birthday, wallet_dir, graft, gpu_subtree, batch_combine, batch_decrypt, local_treestate, treestate_verify_sample, graft_verify_sample, json, keep);
        }
        Cmd::Watch { server, wallet_dir, ufvk, birthday, interval_ms } => {
            cmd_watch(server, wallet_dir, ufvk, birthday, interval_ms);
        }
        Cmd::Oracle { server, wallet_a, wallet_b, ufvk, birthday, sparse_b, write_behind_b, gpu_subtree_b, persist_depth_b, streams, chunk } => {
            cmd_oracle(server, wallet_a, wallet_b, ufvk, birthday, sparse_b, write_behind_b, gpu_subtree_b, persist_depth_b, streams, chunk);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bench_minimal() {
        let cli = Cli::try_parse_from([
            "slipstream", "bench",
            "--server", "https://zec.rocks:443",
            "--ufvk", "uview1abc",
            "--birthday", "2500000",
        ])
        .expect("parses");
        // v0.4.0: graft + batch_combine default ON — bench mirrors production;
        // `--graft false --batch-combine false` is the baseline A/B form.
        assert!(matches!(
            cli.cmd,
            Cmd::Bench { graft: true, batch_combine: true, gpu_subtree: false, keep: false, .. }
        ));
    }

    #[test]
    fn parses_bench_full_flags() {
        let cli = Cli::try_parse_from([
            "slipstream", "bench",
            "--server", "https://zec.rocks:443",
            "--ufvk", "uview1abc",
            "--birthday", "2500000",
            "--wallet-dir", "/tmp/benchw",
            "--graft", "true",
            "--gpu-subtree", "true",
            "--json", "/tmp/out.json",
            "--keep",
        ])
        .expect("parses");
        match cli.cmd {
            Cmd::Bench { graft, gpu_subtree, keep, json, wallet_dir, .. } => {
                assert!(graft && gpu_subtree && keep);
                assert_eq!(json.as_deref(), Some(std::path::Path::new("/tmp/out.json")));
                assert_eq!(wallet_dir.as_deref(), Some(std::path::Path::new("/tmp/benchw")));
            }
            other => panic!("wrong cmd: {other:?}"),
        }
    }

    #[test]
    fn bench_requires_identity() {
        // A bench is always a fresh restore: ufvk + birthday are mandatory.
        assert!(Cli::try_parse_from(["slipstream", "bench", "--server", "http://x:1"]).is_err());
        assert!(
            Cli::try_parse_from([
                "slipstream", "bench",
                "--server", "http://x:1",
                "--ufvk", "uview1abc",
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_version_subcommand() {
        let cli = Cli::try_parse_from(["slipstream", "version"]).expect("parses");
        assert!(matches!(cli.cmd, Cmd::Version));
    }

    #[test]
    fn rejects_unknown_subcommand() {
        assert!(Cli::try_parse_from(["slipstream", "warp"]).is_err());
    }

    #[test]
    fn parse_server_happy_https() {
        let ep = parse_server("https://zec.rocks:443").expect("ok");
        assert_eq!(ep.host, "zec.rocks");
        assert_eq!(ep.port, 443);
        assert!(ep.tls);
    }

    #[test]
    fn parse_server_sad_missing_port() {
        let err = parse_server("https://zec.rocks").unwrap_err();
        assert!(err.contains("port"), "error should mention port: {err}");
    }

    #[test]
    fn parse_server_sad_bad_scheme() {
        let err = parse_server("ftp://zec.rocks:443").unwrap_err();
        assert!(err.contains("http"), "error should mention http: {err}");
    }

    #[test]
    fn parse_range_happy() {
        let (start, end) = parse_range("2500000..2600000").expect("ok");
        assert_eq!(start, 2_500_000);
        assert_eq!(end, 2_600_000);
    }

    #[test]
    fn parse_range_sad_end_before_start() {
        let err = parse_range("2600000..2500000").unwrap_err();
        assert!(err.contains(">="), "error should mention >=: {err}");
    }

    #[test]
    fn parse_range_rejects_inclusive_syntax() {
        let err = parse_range("2500000..=2600000").unwrap_err();
        assert!(err.contains("..="), "error should mention ..=: {err}");
    }

    #[test]
    fn parses_sync_subcommand() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
        ])
        .expect("parses");
        assert!(matches!(cli.cmd, Cmd::Sync { .. }));
    }

    #[test]
    fn sync_parses_sparse_flag() {
        // T6.6: default is now true; bare --sparse with ArgAction::Set still sets true.
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
        ])
        .expect("parses default");
        assert!(matches!(cli.cmd, Cmd::Sync { sparse: true, .. }), "default must be true");
    }

    #[test]
    fn sync_sparse_false_is_overridable() {
        // T6.6: kill switch — `--sparse false` must produce sparse=false.
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
            "--sparse",
            "false",
        ])
        .expect("parses --sparse false");
        assert!(
            matches!(cli.cmd, Cmd::Sync { sparse: false, .. }),
            "--sparse false must override the default"
        );
    }

    #[test]
    fn sync_chunk_split_bytes_defaults_to_engine_default() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
        ])
        .expect("parses default");
        assert!(
            matches!(
                cli.cmd,
                Cmd::Sync {
                    chunk_split_bytes: slipstream_core::EngineConfig::DEFAULT_CHUNK_SPLIT_BYTES,
                    ..
                }
            ),
            "default chunk_split_bytes must equal EngineConfig::DEFAULT_CHUNK_SPLIT_BYTES"
        );
    }

    #[test]
    fn sync_chunk_split_bytes_is_overridable() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
            "--chunk-split-bytes",
            "2097152",
        ])
        .expect("parses --chunk-split-bytes");
        assert!(
            matches!(cli.cmd, Cmd::Sync { chunk_split_bytes: 2_097_152, .. }),
            "--chunk-split-bytes must override the default"
        );
    }

    #[test]
    fn sync_memory_budget_defaults_to_engine_default() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
        ])
        .expect("parses default");
        assert!(
            matches!(
                cli.cmd,
                Cmd::Sync {
                    memory_budget_bytes: slipstream_core::EngineConfig::DEFAULT_MEMORY_BUDGET,
                    ..
                }
            ),
            "default memory_budget_bytes must equal EngineConfig::DEFAULT_MEMORY_BUDGET"
        );
    }

    #[test]
    fn sync_memory_budget_flag_parses() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
            "--memory-budget-bytes",
            "67108864",
        ])
        .expect("parses --memory-budget-bytes");
        assert!(
            matches!(cli.cmd, Cmd::Sync { memory_budget_bytes: 67_108_864, .. }),
            "--memory-budget-bytes must override the default"
        );
    }

    #[test]
    fn sync_rejects_missing_server() {
        // --server is required for Sync
        let result =
            Cli::try_parse_from(["slipstream", "sync", "--wallet-dir", "/tmp/test-wallet"]);
        assert!(result.is_err(), "should fail without --server");
    }

    #[test]
    fn sync_requires_birthday_with_ufvk() {
        // validate_sync_args is a pure function we can call directly.
        let result = validate_sync_args(Some("uview1someufvk"), None);
        assert!(result.is_err(), "ufvk without birthday must error");
        let msg = result.unwrap_err();
        assert!(msg.contains("birthday"), "error message should mention birthday: {msg}");
    }

    #[test]
    fn sync_allows_no_ufvk_no_birthday() {
        let result = validate_sync_args(None, None);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn sync_allows_ufvk_with_birthday() {
        let result = validate_sync_args(Some("uview1someufvk"), Some(800_000));
        assert!(matches!(result, Ok(Some(("uview1someufvk", 800_000)))));
    }

    #[test]
    fn sync_allows_birthday_without_ufvk_returns_none() {
        // birthday with no ufvk: silently ignored (validate_sync_args returns Ok(None))
        let result = validate_sync_args(None, Some(800_000));
        assert!(matches!(result, Ok(None)), "expected Ok(None), got {result:?}");
    }

    #[test]
    fn parses_oracle_subcommand() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "oracle",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-a",
            "/tmp/oa",
            "--wallet-b",
            "/tmp/ob",
            "--ufvk",
            "uview1someufvk",
            "--birthday",
            "1500000",
        ])
        .expect("parses");
        assert!(matches!(cli.cmd, Cmd::Oracle { write_behind_b: false, .. }));
    }

    // ── T6.9 write-behind flags ────────────────────────────────────────────────


    #[test]
    fn sync_write_behind_defaults_on() {
        // T6.9 flip (2026-06-12): default ON; `--write-behind false` is the kill switch.
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
        ])
        .expect("parses without the flag");
        assert!(matches!(cli.cmd, Cmd::Sync { write_behind: true, .. }));
    }

    #[test]
    fn sync_write_behind_bare_flag_enables() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
            "--write-behind",
        ])
        .expect("parses bare --write-behind");
        assert!(matches!(cli.cmd, Cmd::Sync { write_behind: true, .. }));
    }

    #[test]
    fn sync_write_behind_explicit_false_accepted() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
            "--write-behind",
            "false",
        ])
        .expect("parses --write-behind false");
        assert!(matches!(cli.cmd, Cmd::Sync { write_behind: false, .. }));
    }

    #[test]
    fn oracle_write_behind_b_parses() {
        let cli = Cli::try_parse_from([
            "slipstream",
            "oracle",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-a",
            "/tmp/oa",
            "--wallet-b",
            "/tmp/ob",
            "--ufvk",
            "uview1someufvk",
            "--birthday",
            "1500000",
            "--sparse-b",
            "--write-behind-b",
        ])
        .expect("parses");
        assert!(matches!(
            cli.cmd,
            Cmd::Oracle { sparse_b: true, write_behind_b: true, .. }
        ));
    }

    #[test]
    fn gpu_subtree_flags_parse() {
        // oracle --gpu-subtree-b (B0.4 acceptance-gate flag)
        let cli = Cli::try_parse_from([
            "slipstream", "oracle",
            "--server", "http://127.0.0.1:9067",
            "--wallet-a", "/tmp/oa", "--wallet-b", "/tmp/ob",
            "--ufvk", "uview1someufvk", "--birthday", "1500000",
            "--sparse-b", "--gpu-subtree-b",
        ])
        .expect("parses");
        assert!(matches!(cli.cmd, Cmd::Oracle { gpu_subtree_b: true, .. }));

        // sync --gpu-subtree
        let cli = Cli::try_parse_from([
            "slipstream", "sync",
            "--server", "http://127.0.0.1:9067",
            "--wallet-dir", "/tmp/w",
            "--gpu-subtree",
        ])
        .expect("parses");
        assert!(matches!(cli.cmd, Cmd::Sync { gpu_subtree: true, .. }));
    }

    #[test]
    fn persist_depth_flags_parse() {
        // oracle --persist-depth-b
        let cli = Cli::try_parse_from([
            "slipstream", "oracle",
            "--server", "http://127.0.0.1:9067",
            "--wallet-a", "/tmp/oa", "--wallet-b", "/tmp/ob",
            "--ufvk", "uview1someufvk", "--birthday", "1500000",
            "--sparse-b", "--persist-depth-b", "4",
        ])
        .expect("parses");
        assert!(matches!(cli.cmd, Cmd::Oracle { persist_depth_b: 4, .. }));

        // sync --persist-depth
        let cli = Cli::try_parse_from([
            "slipstream", "sync", "--server", "http://127.0.0.1:9067",
            "--wallet-dir", "/tmp/w", "--persist-depth", "3",
        ])
        .expect("parses");
        assert!(matches!(cli.cmd, Cmd::Sync { persist_depth: 3, .. }));

        // default depth = 1
        let cli = Cli::try_parse_from([
            "slipstream", "sync", "--server", "http://127.0.0.1:9067", "--wallet-dir", "/tmp/w",
        ])
        .expect("parses");
        assert!(matches!(cli.cmd, Cmd::Sync { persist_depth: 1, .. }), "default depth must be 1");
    }

    #[test]
    fn require_gpu_feature_noop_when_not_requested() {
        // Must not exit/panic when the flag isn't set, regardless of build features.
        require_gpu_feature_if(false, "--gpu-subtree-b");
        require_gpu_feature_if(false, "--gpu-subtree");
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn require_gpu_feature_ok_when_built_with_gpu() {
        // With the gpu feature on, requesting gpu is allowed (no exit/panic). The
        // exit branch (requested && !feature) can only be covered by a subprocess.
        require_gpu_feature_if(true, "--gpu-subtree-b");
    }

    // ── T8.1 follow flag ──────────────────────────────────────────────────────

    #[test]
    fn sync_follow_flag_parses() {
        // --follow defaults to false.
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
        ])
        .expect("parses without --follow");
        assert!(matches!(cli.cmd, Cmd::Sync { follow: false, .. }), "default must be false");

        // --follow enables following.
        let cli = Cli::try_parse_from([
            "slipstream",
            "sync",
            "--server",
            "http://127.0.0.1:9067",
            "--wallet-dir",
            "/tmp/test-wallet",
            "--follow",
        ])
        .expect("parses --follow");
        assert!(matches!(cli.cmd, Cmd::Sync { follow: true, .. }), "--follow must enable following");
    }
}
