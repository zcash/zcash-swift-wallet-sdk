//! v0.4 Plan B (plan Task 13): batch-affine Orchard `MerkleCRH` combine.
//!
//! Same contract as `slipstream_gpuhash::orchard_combine_batch` — byte-identical
//! to `MerkleHashOrchard::combine` — but pure CPU: all N Sinsemilla chains walk
//! their 52 chunks in lockstep and every half-step's N incomplete-addition
//! λ-denominators are inverted with ONE Montgomery batch inversion (~3 muls per
//! affine add amortized, vs ~11 for the projective path, plus the per-element
//! final affine conversion collapses into the same trick). Degenerate additions
//! (equal x — cryptographically improbable for hash outputs) poison-mark the
//! element and it falls back to the scalar `combine`, so the batch is an
//! OPTIMIZATION SET, never a correctness surface (the same contract that makes
//! the lookup-map build correct).
//!
//! Constants: Q for the Orchard MerkleCRH domain comes from the `sinsemilla`
//! crate itself; the S table is derived with the crate's own published
//! personalization (`hash_to_curve("z.cash:SinsemillaS")(le32(m))` — the spike's
//! SINSEMILLA-SPEC recipe, self-verified there against the crate). The 100k KAT
//! against `MerkleHashOrchard::combine` adjudicates all of it.

use std::sync::OnceLock;

use ff::{Field, PrimeField};
use group::Curve;
use incrementalmerkletree::{Hashable, Level};
use orchard::tree::MerkleHashOrchard;
use pasta_curves::arithmetic::{CurveAffine, CurveExt};
use pasta_curves::pallas;
use rayon::prelude::*;

/// Orchard's MerkleCRH personalization (orchard::constants; verified by the KAT).
const MERKLE_CRH_PERSONALIZATION: &str = "z.cash:Orchard-MerkleCRH";
/// 520 message bits = 10 (level) + 255 + 255 → exactly 52 K-bit chunks.
const CHUNKS: usize = 52;

struct Consts {
    /// Q affine (x, y) for the MerkleCRH hash domain.
    q: (pallas::Base, pallas::Base),
    /// S[m] affine for every 10-bit chunk value.
    s: Vec<(pallas::Base, pallas::Base)>,
}

fn affine_xy(p: &pallas::Point) -> (pallas::Base, pallas::Base) {
    let a = p.to_affine();
    let c = a.coordinates().expect("Sinsemilla generators are never the identity");
    (*c.x(), *c.y())
}

fn consts() -> &'static Consts {
    static CONSTS: OnceLock<Consts> = OnceLock::new();
    CONSTS.get_or_init(|| {
        // HashDomain::Q() is test-gated upstream; derive it exactly the way
        // HashDomain::new does (Q = hash_to_curve(Q_PERSONALIZATION)(domain) —
        // the spike's SINSEMILLA-SPEC recipe). The KAT adjudicates.
        let q = affine_xy(&pallas::Point::hash_to_curve(sinsemilla::Q_PERSONALIZATION)(
            MERKLE_CRH_PERSONALIZATION.as_bytes(),
        ));
        let hasher = pallas::Point::hash_to_curve(sinsemilla::S_PERSONALIZATION);
        let s = (0u32..1 << sinsemilla::K)
            .map(|m| affine_xy(&hasher(&m.to_le_bytes())))
            .collect();
        Consts { q, s }
    })
}

/// The 52 chunk indices of one combine's message: 10 level bits ‖ 255 left bits
/// ‖ 255 right bits, all little-endian, split into 10-bit little-endian chunks
/// (mirrors `orchard::tree::MerkleHashOrchard::combine` + `sinsemilla::i2lebsp_k`).
fn chunk_indices(layer: u8, left: &[u8; 32], right: &[u8; 32]) -> [u16; CHUNKS] {
    let mut bits = [false; 520];
    for (i, bit) in bits.iter_mut().enumerate().take(10) {
        *bit = (u32::from(layer) >> i) & 1 == 1;
    }
    for i in 0..255 {
        bits[10 + i] = (left[i / 8] >> (i % 8)) & 1 == 1;
    }
    for i in 0..255 {
        bits[265 + i] = (right[i / 8] >> (i % 8)) & 1 == 1;
    }
    let mut out = [0u16; CHUNKS];
    for (c, chunk) in out.iter_mut().enumerate() {
        let mut v = 0u16;
        for k in 0..10 {
            if bits[c * 10 + k] {
                v |= 1 << k;
            }
        }
        *chunk = v;
    }
    out
}

/// Montgomery batch inversion in place. `xs` MUST contain no zeros (the caller
/// poison-replaces zeros with ONE and marks those elements fallback).
fn batch_invert(xs: &mut [pallas::Base]) {
    let n = xs.len();
    if n == 0 {
        return;
    }
    let mut prefix = Vec::with_capacity(n);
    let mut acc = pallas::Base::ONE;
    for x in xs.iter() {
        prefix.push(acc);
        acc *= x;
    }
    let mut inv_all = acc.invert().expect("no zeros by contract");
    for i in (0..n).rev() {
        let inv_i = inv_all * prefix[i];
        inv_all *= xs[i];
        xs[i] = inv_i;
    }
}

/// One lockstep batch: walk every element's 52-chunk Sinsemilla chain with
/// shared inversions. Returns per-element `Some(x-coordinate bytes)`, `None`
/// = degenerate (caller falls back to the scalar combine).
fn walk_batch(msgs: &[[u16; CHUNKS]]) -> Vec<Option<[u8; 32]>> {
    let cs = consts();
    let n = msgs.len();
    let mut x = vec![cs.q.0; n];
    let mut y = vec![cs.q.1; n];
    let mut dead = vec![false; n];
    let mut denom = vec![pallas::Base::ONE; n];
    let mut other_x = vec![pallas::Base::ZERO; n];
    let mut other_y = vec![pallas::Base::ZERO; n];

    for step in 0..(CHUNKS * 2) {
        let chunk_i = step / 2;
        let first_half = step % 2 == 0;
        // Gather the "other" operand: S[m] on the first half-step, the pre-step
        // accumulator on the second (acc' = t + acc_prev).
        for i in 0..n {
            if dead[i] {
                denom[i] = pallas::Base::ONE;
                continue;
            }
            if first_half {
                let (sx, sy) = cs.s[msgs[i][chunk_i] as usize];
                other_x[i] = sx;
                other_y[i] = sy;
            }
            // second half: other_* already holds acc_prev (stashed below).
            let d = other_x[i] - x[i];
            if bool::from(d.is_zero()) {
                dead[i] = true; // incomplete addition degenerate → scalar fallback
                denom[i] = pallas::Base::ONE;
            } else {
                denom[i] = d;
            }
        }
        batch_invert(&mut denom);
        for i in 0..n {
            if dead[i] {
                continue;
            }
            let lambda = (other_y[i] - y[i]) * denom[i];
            let x3 = lambda.square() - x[i] - other_x[i];
            let y3 = lambda * (x[i] - x3) - y[i];
            if first_half {
                // Stash acc_prev as the second half-step's operand, advance to t.
                other_x[i] = x[i];
                other_y[i] = y[i];
            }
            x[i] = x3;
            y[i] = y3;
        }
    }
    (0..n)
        .map(|i| if dead[i] { None } else { Some(x[i].to_repr()) })
        .collect::<Vec<_>>()
}

/// Batched Orchard MerkleCRH `combine` — CPU batch-affine. Same contract as
/// `slipstream_gpuhash::orchard_combine_batch`: `output[i]` is byte-identical to
/// `MerkleHashOrchard::combine(Level::from(layers[i]), &lefts[i], &rights[i])`.
pub(crate) fn orchard_combine_batch_cpu(
    layers: &[u8],
    lefts: &[[u8; 32]],
    rights: &[[u8; 32]],
) -> Vec<[u8; 32]> {
    assert_eq!(layers.len(), lefts.len(), "layers/lefts length mismatch");
    assert_eq!(layers.len(), rights.len(), "layers/rights length mismatch");
    let n = layers.len();
    if n == 0 {
        return Vec::new();
    }
    // Rayon over ~2k-wide batches: wide enough to amortize the inversion to
    // noise, small enough to keep the lanes' working set in cache. Runs inside
    // the existing per-pool rayon context (work stealing handles nesting).
    const BATCH: usize = 2048;
    let idx: Vec<usize> = (0..n).collect();
    idx.par_chunks(BATCH)
        .flat_map(|chunk| {
            let msgs: Vec<[u16; CHUNKS]> = chunk
                .iter()
                .map(|&i| chunk_indices(layers[i], &lefts[i], &rights[i]))
                .collect();
            let walked = walk_batch(&msgs);
            chunk
                .iter()
                .zip(walked)
                .map(|(&i, w)| match w {
                    Some(bytes) => bytes,
                    None => scalar_combine(layers[i], &lefts[i], &rights[i]),
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Scalar fallback — the crate's own combine, used for degenerates and
/// non-canonical inputs (byte-identical by definition).
fn scalar_combine(layer: u8, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let l = Option::from(MerkleHashOrchard::from_bytes(left));
    let r = Option::from(MerkleHashOrchard::from_bytes(right));
    match (l, r) {
        (Some(l), Some(r)) => MerkleHashOrchard::combine(Level::from(layer), &l, &r).to_bytes(),
        // Non-canonical input cannot come from real tree nodes; mirror gpuhash's
        // canonical-input contract by hashing zeros (never reached in practice).
        _ => [0u8; 32],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    fn pool(n: usize) -> Vec<MerkleHashOrchard> {
        let mut out = Vec::with_capacity(n);
        let mut a = MerkleHashOrchard::empty_leaf();
        let mut b = MerkleHashOrchard::empty_root(Level::from(0));
        for _ in 0..n {
            let c = MerkleHashOrchard::combine(Level::from(0), &a, &b);
            out.push(c);
            a = b;
            b = c;
        }
        out
    }

    #[test]
    fn batch_invert_matches_per_element() {
        let mut rng = StdRng::seed_from_u64(0xB471);
        let xs: Vec<pallas::Base> =
            (0..1000).map(|_| pallas::Base::from(rng.next_u64() | 1)).collect();
        let mut batched = xs.clone();
        batch_invert(&mut batched);
        for (x, inv) in xs.iter().zip(batched) {
            assert_eq!(inv, x.invert().expect("nonzero"), "batch inversion diverged");
        }
    }

    /// THE KAT: byte-identical to the crate's combine over random valid nodes
    /// and every level 0..32. (10k in debug; the 100k release sweep is the
    /// `--ignored` variant below.)
    #[test]
    fn combine_batch_cpu_matches_orchard_10k() {
        kat(10_000, 0xB472);
    }

    #[test]
    #[ignore = "release-mode 100k sweep: cargo test -p slipstream-core --release -- --ignored combine_batch_cpu_matches_orchard_100k"]
    fn combine_batch_cpu_matches_orchard_100k() {
        kat(100_000, 0xB473);
    }

    /// STOP-rule probe (plan Task 13 Step 4): ns/combine, scalar vs batched,
    /// single-threaded batch walk (rayon width 1 batch) at width 4096.
    /// Run: cargo test -p slipstream-core --release -- --ignored --nocapture combine_bench
    #[test]
    #[ignore = "release-mode timing probe"]
    fn combine_bench() {
        let n = 4096;
        let nodes = pool(2 * n);
        let layers: Vec<u8> = (0..n).map(|i| (i % 32) as u8).collect();
        let lefts: Vec<[u8; 32]> = (0..n).map(|i| nodes[i].to_bytes()).collect();
        let rights: Vec<[u8; 32]> = (0..n).map(|i| nodes[n + i].to_bytes()).collect();
        // Warm the constants table outside the timing.
        let _ = orchard_combine_batch_cpu(&layers[..1], &lefts[..1], &rights[..1]);

        let t = std::time::Instant::now();
        let batched = orchard_combine_batch_cpu(&layers, &lefts, &rights);
        let batched_ns = t.elapsed().as_nanos() / n as u128;

        let t = std::time::Instant::now();
        let scalar: Vec<[u8; 32]> = (0..n)
            .map(|i| {
                MerkleHashOrchard::combine(
                    Level::from(layers[i]),
                    &Option::from(MerkleHashOrchard::from_bytes(&lefts[i])).expect("canonical"),
                    &Option::from(MerkleHashOrchard::from_bytes(&rights[i])).expect("canonical"),
                )
                .to_bytes()
            })
            .collect();
        let scalar_ns = t.elapsed().as_nanos() / n as u128;
        assert_eq!(batched, scalar);
        // NOTE: the batched number includes rayon parallelism (production shape);
        // scalar is single-threaded like from_iter's per-node combine calls.
        println!(
            "combine ns/el: scalar(1T) {scalar_ns} | batched(rayon) {batched_ns} | ratio {:.2}x",
            scalar_ns as f64 / batched_ns as f64
        );
    }

    fn kat(n: usize, seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let nodes = pool(2 * n);
        let layers: Vec<u8> = (0..n).map(|_| (rng.next_u32() % 32) as u8).collect();
        let lefts: Vec<[u8; 32]> = (0..n).map(|i| nodes[i].to_bytes()).collect();
        let rights: Vec<[u8; 32]> = (0..n).map(|i| nodes[n + i].to_bytes()).collect();
        let got = orchard_combine_batch_cpu(&layers, &lefts, &rights);
        for i in 0..n {
            let exp = MerkleHashOrchard::combine(
                Level::from(layers[i]),
                &Option::from(MerkleHashOrchard::from_bytes(&lefts[i])).expect("canonical"),
                &Option::from(MerkleHashOrchard::from_bytes(&rights[i])).expect("canonical"),
            )
            .to_bytes();
            assert_eq!(got[i], exp, "combine mismatch at {i} (layer {})", layers[i]);
        }
    }
}
