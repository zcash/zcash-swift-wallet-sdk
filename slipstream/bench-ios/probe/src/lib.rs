//! v0.4 P0 bench-ios probe (spec §3.4): C ABI around ONE engine bench pass.
//! The SwiftUI host (../app) calls `slipstream_bench_run`; the probe runs the
//! same fresh-restore path `slipstream-cli bench` uses (sync_once + the
//! engine-written BenchSummary JSON) and hands the JSON back through the
//! caller's buffer. Identity is a UFVK — keys never cross the engine boundary.

use std::ffi::{CStr, c_char};
use std::path::PathBuf;

/// Return codes for `slipstream_bench_run` (mirrored in include/slipstream_bench.h).
pub const BENCH_OK: i32 = 0;
pub const BENCH_ERR_ARGS: i32 = -1;
pub const BENCH_ERR_SYNC: i32 = -2;
pub const BENCH_ERR_DIRTY_DIR: i32 = -3;
pub const BENCH_ERR_BUFFER: i32 = -4;

/// Copy `json` into the caller's buffer as a NUL-terminated C string.
/// A too-small buffer is an ERROR (never a silent truncation — a truncated
/// bench artifact is worse than none).
pub fn write_json_to_buf(json: &str, out: *mut c_char, cap: usize) -> i32 {
    if out.is_null() || json.is_empty() {
        return BENCH_ERR_ARGS;
    }
    let bytes = json.as_bytes();
    if bytes.len() + 1 > cap {
        return BENCH_ERR_BUFFER;
    }
    // SAFETY: caller guarantees `out` points at `cap` writable bytes (the C
    // contract in slipstream_bench.h); we checked len+1 <= cap above.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out.cast::<u8>(), bytes.len());
        *out.add(bytes.len()) = 0;
    }
    BENCH_OK
}

fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    // SAFETY: caller passes NUL-terminated strings (the C contract).
    unsafe { CStr::from_ptr(p) }.to_str().ok()
}

/// Run ONE fresh-restore bench pass and hand back the engine-written
/// BenchSummary JSON. Blocking — call off the main thread.
///
/// * `server`      — lightwalletd URL, e.g. "https://zec.rocks:443"
/// * `ufvk`        — viewing key of the reference wallet
/// * `birthday`    — restore birthday height
/// * `wallet_dir`  — writable dir that must NOT already hold a data.db
///                   (a bench is a fresh restore; pass a new subdir per run)
/// * `gpu_subtree` — banked B0 lever (needs a `gpu`-feature build; no-ops otherwise
///                   is impossible: the engine build without the feature ignores it,
///                   so the app surfaces the flag only on gpu builds)
/// * `out_json`/`cap` — caller buffer for the NUL-terminated JSON (64 KiB is plenty)
///
/// Returns BENCH_OK or a BENCH_ERR_* code.
///
/// # Safety
/// All pointer args follow the C contract above: strings are valid
/// NUL-terminated UTF-8, `out_json` points at `cap` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn slipstream_bench_run(
    server: *const c_char,
    ufvk: *const c_char,
    birthday: u32,
    wallet_dir: *const c_char,
    gpu_subtree: bool,
    out_json: *mut c_char,
    cap: usize,
) -> i32 {
    // Engine logs → os console (Xcode). Once per process; ignore re-init errors.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .try_init();

    let (Some(server), Some(ufvk), Some(dir)) = (cstr(server), cstr(ufvk), cstr(wallet_dir))
    else {
        return BENCH_ERR_ARGS;
    };
    let Some(endpoint) = parse_endpoint(server) else {
        return BENCH_ERR_ARGS;
    };
    let dir = PathBuf::from(dir);
    if dir.join("data.db").exists() {
        return BENCH_ERR_DIRTY_DIR;
    }
    if std::fs::create_dir_all(&dir).is_err() {
        return BENCH_ERR_ARGS;
    }

    let json_path = dir.join("bench.json");
    let mut cfg = slipstream_core::EngineConfig::new(
        slipstream_core::Network::MainNetwork,
        dir.join("data.db"),
        endpoint,
    );
    cfg.gpu_subtree = gpu_subtree;
    cfg.bench_json_path = Some(json_path.clone());

    let Ok(rt) = tokio::runtime::Runtime::new() else {
        return BENCH_ERR_SYNC;
    };
    let result = rt.block_on(slipstream_core::engine::sync_once(
        &cfg,
        Some((ufvk, u64::from(birthday))),
        None,
        None,
    ));
    if result.is_err() {
        return BENCH_ERR_SYNC;
    }
    match std::fs::read_to_string(&json_path) {
        Ok(json) => write_json_to_buf(&json, out_json, cap),
        Err(_) => BENCH_ERR_SYNC,
    }
}

/// "http(s)://host:port" → Endpoint. Minimal on purpose (the app prefills a
/// known-good default); mirrors the CLI's accepted shapes.
fn parse_endpoint(s: &str) -> Option<slipstream_core::Endpoint> {
    let (tls, rest) = if let Some(r) = s.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = s.strip_prefix("http://") {
        (false, r)
    } else {
        return None;
    };
    let (host, port) = rest.trim_end_matches('/').rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some(slipstream_core::Endpoint { host: host.to_string(), port, tls })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trips_through_the_c_buffer() {
        let json = r#"{"total_s":1.5,"blocks":42}"#;
        let mut buf = vec![0 as c_char; 64];
        let rc = write_json_to_buf(json, buf.as_mut_ptr(), buf.len());
        assert_eq!(rc, BENCH_OK);
        let out = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert_eq!(out.to_str().expect("utf8"), json);
    }

    #[test]
    fn buffer_too_small_is_an_error_not_a_truncation() {
        let json = "0123456789";
        // 10 bytes of payload + NUL needs 11; give 10.
        let mut buf = vec![0 as c_char; 10];
        assert_eq!(write_json_to_buf(json, buf.as_mut_ptr(), buf.len()), BENCH_ERR_BUFFER);
    }

    #[test]
    fn empty_and_null_are_rejected() {
        assert_eq!(write_json_to_buf("x", std::ptr::null_mut(), 8), BENCH_ERR_ARGS);
        let mut buf = vec![0 as c_char; 8];
        assert_eq!(write_json_to_buf("", buf.as_mut_ptr(), buf.len()), BENCH_ERR_ARGS);
    }

    #[test]
    fn endpoint_parses_the_cli_shapes() {
        let e = parse_endpoint("https://zec.rocks:443").expect("https");
        assert!((e.host.as_str(), e.port, e.tls) == ("zec.rocks", 443, true));
        let e = parse_endpoint("http://127.0.0.1:9067/").expect("http + trailing slash");
        assert!((e.host.as_str(), e.port, e.tls) == ("127.0.0.1", 9067, false));
        assert!(parse_endpoint("zec.rocks:443").is_none(), "scheme required");
        assert!(parse_endpoint("https://zec.rocks").is_none(), "port required");
    }

    #[test]
    fn dirty_wallet_dir_is_refused() {
        let td = tempfile::tempdir().expect("tempdir");
        std::fs::write(td.path().join("data.db"), b"x").expect("touch data.db");
        let server = std::ffi::CString::new("http://127.0.0.1:1").expect("cstr");
        let ufvk = std::ffi::CString::new("uview1abc").expect("cstr");
        let dir = std::ffi::CString::new(td.path().to_str().expect("utf8 path")).expect("cstr");
        let mut buf = vec![0 as c_char; 128];
        // SAFETY: valid NUL-terminated strings + a real buffer (the C contract).
        let rc = unsafe {
            slipstream_bench_run(
                server.as_ptr(),
                ufvk.as_ptr(),
                2_500_000,
                dir.as_ptr(),
                false,
                buf.as_mut_ptr(),
                buf.len(),
            )
        };
        assert_eq!(rc, BENCH_ERR_DIRTY_DIR, "must refuse a pre-populated wallet dir");
    }
}
