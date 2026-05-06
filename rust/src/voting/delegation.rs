use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use anyhow::anyhow;
use ff::PrimeField;
use ffi_helpers::panic::catch_panic;
use pasta_curves::pallas;
use zcash_voting::{self as voting, zkp1};

use crate::{unwrap_exc_or, unwrap_exc_or_null};

use super::db::VotingDatabaseHandle;
use super::helpers::{json_to_boxed_slice, str_from_ptr};
use super::json::{JsonDelegationPirPrecomputeResult, JsonNoteInfo};

// Keep PIR client construction at the SDK boundary so zcash_voting can accept
// an injected transport. Today we use direct Hyper/Rustls. In the future this will be the
// single place to add a Tor-backed transport based on SDK configuration.
fn connect_pir_client(pir_url: &str) -> anyhow::Result<voting::PirClientBlocking> {
    voting::PirClientBlocking::with_transport(pir_url, Arc::new(voting::HyperTransport::new()))
        .map_err(|e| anyhow!("connect to PIR server failed: {}", e))
}

/// Precompute and cache delegation PIR IMT proofs for ZKP #1.
///
/// Returns JSON-encoded `DelegationPirPrecomputeResult` as `*mut FfiBoxedSlice`,
/// or null on error.
///
/// # Safety
///
/// - `db` must be a valid, non-null `VotingDatabaseHandle` pointer.
/// - All pointer/length pairs must be valid for reads for their stated lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_precompute_delegation_pir(
    db: *mut VotingDatabaseHandle,
    round_id: *const u8,
    round_id_len: usize,
    bundle_index: u32,
    notes_json: *const u8,
    notes_json_len: usize,
    pir_server_url: *const u8,
    pir_server_url_len: usize,
    network_id: u32,
) -> *mut crate::ffi::BoxedSlice {
    let db = AssertUnwindSafe(db);
    let res = catch_panic(|| {
        let handle =
            unsafe { db.as_ref() }.ok_or_else(|| anyhow!("VotingDatabaseHandle is null"))?;
        let round_id_str = unsafe { str_from_ptr(round_id, round_id_len) }?;
        let notes_bytes = unsafe { std::slice::from_raw_parts(notes_json, notes_json_len) };
        let json_notes: Vec<JsonNoteInfo> = serde_json::from_slice(notes_bytes)?;
        let core_notes: Vec<voting::NoteInfo> = json_notes.into_iter().map(Into::into).collect();
        let pir_url = unsafe { str_from_ptr(pir_server_url, pir_server_url_len) }?;
        let pir_client = connect_pir_client(&pir_url)?;

        let result = handle
            .db
            .precompute_delegation_pir(
                &round_id_str,
                bundle_index,
                &core_notes,
                &pir_client,
                network_id,
            )
            .map_err(|e| anyhow!("precompute_delegation_pir failed: {}", e))?;

        let json_result: JsonDelegationPirPrecomputeResult = result.into();
        json_to_boxed_slice(&json_result)
    });
    unwrap_exc_or_null(res)
}

/// Validate a PIR-fetched IMT non-membership proof bytewise.
///
/// Inputs are the wire format of `zcash_voting::ImtProofData`: 32-byte LE
/// pallas::Base values for the root and the three nf_bounds, a u32 leaf
/// position, and 29 32-byte path siblings.
///
/// Returns 0 if the proof is valid, 1 if it is well-formed but invalid, and -1
/// if inputs are malformed or a panic occurs.
///
/// # Safety
///
/// - `root`, `nullifier`, and `expected_root` must each point to exactly 32 bytes.
/// - `nf_bounds` must point to exactly 96 bytes (3 * 32).
/// - `path` must point to exactly 928 bytes (29 * 32).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_voting_validate_pir_proof(
    root: *const u8,
    nf_bounds: *const u8,
    leaf_pos: u32,
    path: *const u8,
    nullifier: *const u8,
    expected_root: *const u8,
) -> i32 {
    let res = catch_panic(|| {
        let root_bytes: [u8; 32] = unsafe { std::slice::from_raw_parts(root, 32) }
            .try_into()
            .map_err(|_| anyhow!("root must be exactly 32 bytes"))?;
        let nf_bounds_bytes = unsafe { std::slice::from_raw_parts(nf_bounds, 96) };
        let path_bytes = unsafe { std::slice::from_raw_parts(path, 928) };
        let nullifier_bytes: [u8; 32] = unsafe { std::slice::from_raw_parts(nullifier, 32) }
            .try_into()
            .map_err(|_| anyhow!("nullifier must be exactly 32 bytes"))?;
        let expected_root_bytes: [u8; 32] =
            unsafe { std::slice::from_raw_parts(expected_root, 32) }
                .try_into()
                .map_err(|_| anyhow!("expected_root must be exactly 32 bytes"))?;

        let proof = zcash_voting::ImtProofData {
            root: parse_base(&root_bytes, "root")?,
            nf_bounds: [
                parse_base(&nf_bounds_bytes[0..32], "nf_bounds[0]")?,
                parse_base(&nf_bounds_bytes[32..64], "nf_bounds[1]")?,
                parse_base(&nf_bounds_bytes[64..96], "nf_bounds[2]")?,
            ],
            leaf_pos,
            path: parse_path(path_bytes)?,
        };

        let nullifier = parse_base(&nullifier_bytes, "nullifier")?;
        let expected_root = parse_base(&expected_root_bytes, "expected_root")?;

        match zkp1::validate_and_convert_pir_proof(proof, nullifier, expected_root) {
            Ok(_) => Ok(0),
            Err(_) => Ok(1),
        }
    });
    unwrap_exc_or(res, -1)
}

fn parse_base(bytes: &[u8], label: &str) -> anyhow::Result<pallas::Base> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("{label} must be exactly 32 bytes"))?;
    Option::from(pallas::Base::from_repr(bytes))
        .ok_or_else(|| anyhow!("{label} is not a canonical pallas::Base encoding"))
}

fn parse_path(bytes: &[u8]) -> anyhow::Result<[pallas::Base; 29]> {
    let mut path = [pallas::Base::from(0); 29];
    for (i, chunk) in bytes.chunks_exact(32).enumerate() {
        path[i] = parse_base(chunk, "path element")?;
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden proof generated from zcash_voting's test-only TestImt helper:
    // https://github.com/valargroup/zcash_voting/blob/zcash_voting-v0.5.2/zcash_voting/src/zkp1.rs#L573-L708
    // Keeping the fixture as bytes preserves FFI coverage without direct SDK
    // dev-dependencies on halo2_gadgets or voting-circuits internals.
    const ROOT: &str = "8a9fa2daeb635fbb006af674259cea05e59d71b9a4773e7433942a14ab031801";
    const NF_BOUNDS: &str = "000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
    const LEAF_POS: u32 = 0;
    const PATH: &str = "f74380b8dc56b22c3d19c3340538fc374793eb8e87708f41ab73175bf12cca36277c1d54340089c6663e1ffa57fb1c4a097e43952509c9386a6522193cdefb2f6b8c704532a36bb22740da9f2831ff31e0645d22787f5c0bce77e3b8d75eaf2843f92cf5b9836a092e0765640c492a4bc84a830621031e28a7857fca2149e833086e0db15e3d4ba38490e912c1fdbe267fedf4a707ccb28d621647ab77e29c307c790e41edc9df0f750fe03799eb7b5ede2c9d833569df4bd43a6b46e2214510f3e160b7b9a3d21fadd88d9316cb35f61fb07404e79b6b019d2fe570d57a8335c17184fa579ec144ca5b7093e61550dd9b9fabfaf9822815509d7df99846d402421cd5367dca2ceaa6610949b3cc3365c8e24eff6b7a430d51f79a42e55be52db6b3d188445aff0456047f951714a26920a0a0d0d02eaef1f802a0ea1394fd1b6c4edd9a05510f352bf6e35450e42c71abba35f1d0853a5c4faaba2861384d1538c031808c91140538602e8454283e9c5cfd47564c267f0815aae2d1dac4842d52f55784572f5a4ddbde392035bbe5619a86ec2db7dbca75ee6081b6dd6ab726f8254dd893ec76266b8b7dc66c70011f958767558a461a6143f0eb100693423819863eeddc19d02343311d5073ce3e931fdb19b745755a7e925818201c6346015827f3a7c07a65bd137df252fbd4379f6ef59601cd19d9c7d89d85634263cc04689b97d136dfa9f2457502788d5407d53d9a04c6d8d8732e7283f9f7b0a3531a728584a001839fc736a82d711de75d4d97b60a1432aa06873dbfada599a73a027fd25eefa6e305a354af3002c07fd283b5bdf1dc00502f0957ef3150ce9e020dfade15e2bfe919f9867c69c69b17c3aae833bf3f71fa6044748daab6779b020535813867047cdf120108e15fcc1257e42709fe6bfdcba82cb43c7be467562211564f02b6c295c7ee794a223f832c9aea620c634cd447c91a102497d1cf7b8a31e97207509990c7253c37300480fd747489cf99cf23d5ab7c7991d1a725714a092f0f453af80b9d7d6828742f9fad934eefea1cd3a281b396e40b3b804e27de3b6fc3b07e82930f463606951a5b0ddcf8b63e4cebf88387f4be2cca1446dd7f3715076183e96f5e260b2008e52fa71f57dbfb958ceaf42d99d54fdf6da7bd343b7ff965aeb8d2753f923ea9d1bf6df39de61763c145550f3748f049ba5a1bb42160420d736b7e3a9f172e40d98e3decff6a759ca472043254f7c639b9fcae001353d53603c500bc474aef03cde95a101a7dde4fccadb8379407e3f479044ef316";
    const NULLIFIER: &str = "0100000000000000000000000000000000000000000000000000000000000000";
    const EXPECTED_ROOT: &str = "8a9fa2daeb635fbb006af674259cea05e59d71b9a4773e7433942a14ab031801";

    fn decode_hex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2);
        let mut out = [0u8; N];
        for i in 0..N {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    fn validate(
        proof_root: &[u8; 32],
        nf_bounds: &[u8; 96],
        leaf_pos: u32,
        path: &[u8; 928],
        nullifier: &[u8; 32],
        expected_root: &[u8; 32],
    ) -> i32 {
        unsafe {
            zcashlc_voting_validate_pir_proof(
                proof_root.as_ptr(),
                nf_bounds.as_ptr(),
                leaf_pos,
                path.as_ptr(),
                nullifier.as_ptr(),
                expected_root.as_ptr(),
            )
        }
    }

    #[test]
    fn validate_pir_proof_accepts_valid() {
        let root = decode_hex::<32>(ROOT);
        let nf_bounds = decode_hex::<96>(NF_BOUNDS);
        let path = decode_hex::<928>(PATH);
        let nullifier = decode_hex::<32>(NULLIFIER);
        let expected_root = decode_hex::<32>(EXPECTED_ROOT);

        assert_eq!(
            validate(
                &root,
                &nf_bounds,
                LEAF_POS,
                &path,
                &nullifier,
                &expected_root
            ),
            0
        );
    }

    #[test]
    fn validate_pir_proof_rejects_root_mismatch() {
        let root = decode_hex::<32>(ROOT);
        let nf_bounds = decode_hex::<96>(NF_BOUNDS);
        let path = decode_hex::<928>(PATH);
        let nullifier = decode_hex::<32>(NULLIFIER);
        let mut expected_root = decode_hex::<32>(EXPECTED_ROOT);
        expected_root[0] ^= 1;

        assert_eq!(
            validate(
                &root,
                &nf_bounds,
                LEAF_POS,
                &path,
                &nullifier,
                &expected_root
            ),
            1
        );
    }

    #[test]
    fn validate_pir_proof_rejects_corrupted_path() {
        let root = decode_hex::<32>(ROOT);
        let nf_bounds = decode_hex::<96>(NF_BOUNDS);
        let mut path = decode_hex::<928>(PATH);
        let nullifier = decode_hex::<32>(NULLIFIER);
        let expected_root = decode_hex::<32>(EXPECTED_ROOT);
        path[0] ^= 1;

        assert_eq!(
            validate(
                &root,
                &nf_bounds,
                LEAF_POS,
                &path,
                &nullifier,
                &expected_root
            ),
            1
        );
    }

    #[test]
    fn validate_pir_proof_rejects_non_canonical_field_encoding() {
        let nf_bounds = decode_hex::<96>(NF_BOUNDS);
        let path = decode_hex::<928>(PATH);
        let non_canonical_root = [0xff; 32];
        let nullifier = decode_hex::<32>(NULLIFIER);
        let expected_root = decode_hex::<32>(EXPECTED_ROOT);

        assert_eq!(
            validate(
                &non_canonical_root,
                &nf_bounds,
                LEAF_POS,
                &path,
                &nullifier,
                &expected_root
            ),
            -1
        );
    }

    #[test]
    fn precompute_delegation_pir_rejects_null_db() {
        let result = unsafe {
            zcashlc_voting_precompute_delegation_pir(
                std::ptr::null_mut(),
                std::ptr::null(),
                0,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                0,
            )
        };

        assert!(result.is_null());
    }
}
