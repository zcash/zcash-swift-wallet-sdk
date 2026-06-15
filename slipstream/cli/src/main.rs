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
    let drain = tokio::spawn(async move { while let Some((_c, _p)) = rx.recv().await {} });
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

        let result = slipstream_core::engine::sync_once(&cfg, ufvk_arg, Some(progress)).await;

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

                // ── T8.1 follow loop (CLI variant) ──────────────────────────
                // When --follow is set, keep polling the tip and running catch-up
                // passes until Ctrl-C. The jittered sleep matches the FFI follow
                // loop's randomised cadence (FOLLOW_POLL_MIN_SECS=10 ..
                // FOLLOW_POLL_MAX_SECS=30), using the same range for consistency.
                if follow {
                    // CLI-local jitter: same [10, 30] range as the FFI loop.
                    const FOLLOW_CLI_POLL_MIN: u64 = 10;
                    const FOLLOW_CLI_POLL_MAX: u64 = 30;

                    let mut last_tip = outcome.chain_tip;
                    println!("follow: watching for new blocks (Ctrl-C to stop) ...");
                    loop {
                        // Jittered sleep.
                        let span = (FOLLOW_CLI_POLL_MAX - FOLLOW_CLI_POLL_MIN + 1) as f64;
                        let sample = rand::random::<f64>();
                        let offset = (sample * span) as u64;
                        let secs = FOLLOW_CLI_POLL_MIN
                            + offset.min(FOLLOW_CLI_POLL_MAX - FOLLOW_CLI_POLL_MIN);
                        println!("follow: sleeping {secs}s ...");
                        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;

                        // Cheap probe.
                        match slipstream_core::engine::probe_tip(&cfg).await {
                            Ok(observed) => {
                                if !slipstream_core::engine::should_resync(last_tip, observed) {
                                    println!("follow: tip unchanged ({observed}), no pass needed");
                                    continue;
                                }
                                println!(
                                    "follow: tip advanced {last_tip} → {observed}, syncing ..."
                                );
                                match slipstream_core::engine::sync_once(
                                    &cfg,
                                    None, // keyless: account already imported
                                    None,
                                )
                                .await
                                {
                                    Ok(fo) => {
                                        last_tip = fo.chain_tip;
                                        println!(
                                            "follow pass: +{} blocks, tip={}, txs={}",
                                            fo.report.scan.blocks,
                                            fo.chain_tip,
                                            fo.enhance.txs_stored
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!("follow pass failed: {e}");
                                        std::process::exit(1);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("follow probe failed: {e}");
                                // Non-fatal for the CLI (mirrors the FFI transient tolerance):
                                // just warn and try again next iteration.
                                println!("follow: probe error — will retry next cycle");
                            }
                        }
                    }
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
        let a = slipstream_core::engine::sync_once(&mk_cfg(&wallet_a, false, false, false, 1), Some((ufvk.as_str(), birthday)), None).await?;
        println!("oracle: run A done — tip {} in {:.1?}", a.chain_tip, a.elapsed);
        println!("oracle: run B (sparse_b={sparse_b} write_behind_b={write_behind_b} gpu_subtree_b={gpu_subtree_b} persist_depth_b={persist_depth_b}) …");
        let b = slipstream_core::engine::sync_once(&mk_cfg(&wallet_b, sparse_b, write_behind_b, gpu_subtree_b, persist_depth_b), Some((ufvk.as_str(), birthday)), None).await?;
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
        Cmd::Sync { server, wallet_dir, ufvk, birthday, streams, chunk, sparse, chunk_split_bytes, write_behind, gpu_subtree, persist_depth, follow } => {
            cmd_sync(server, wallet_dir, ufvk, birthday, streams, chunk, sparse, chunk_split_bytes, write_behind, gpu_subtree, persist_depth, follow);
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
