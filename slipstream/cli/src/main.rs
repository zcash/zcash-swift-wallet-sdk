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
    let stats = slipstream_core::fetch::run_fetch(endpoint, plan, tx).await?;
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

fn cmd_sync(
    server: String,
    wallet_dir: std::path::PathBuf,
    ufvk: Option<String>,
    birthday: Option<u64>,
    streams: usize,
    chunk: u32,
) {
    let endpoint = parse_server(&server).unwrap_or_else(|e| { eprintln!("{e}"); std::process::exit(2) });

    let ufvk_arg = validate_sync_args(ufvk.as_deref(), birthday)
        .unwrap_or_else(|e| { eprintln!("error: {e}"); std::process::exit(2) });

    let mut cfg = slipstream_core::EngineConfig::new(
        slipstream_core::Network::MainNetwork,
        wallet_dir.join("data.db"),
        endpoint,
    );
    cfg.fetch_streams = streams;
    cfg.chunk_blocks = chunk;

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        match slipstream_core::engine::sync_once(&cfg, ufvk_arg).await {
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
            }
            Err(e) => {
                eprintln!("sync failed: {e}");
                std::process::exit(1);
            }
        }
    });
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
        Cmd::Sync { server, wallet_dir, ufvk, birthday, streams, chunk } => {
            cmd_sync(server, wallet_dir, ufvk, birthday, streams, chunk);
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
}
