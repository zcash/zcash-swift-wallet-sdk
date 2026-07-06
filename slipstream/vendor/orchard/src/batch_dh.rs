//! [slipstream fork] Batched same-scalar Diffie–Hellman for trial decryption.
//!
//! Trial decryption multiplies MANY ephemeral keys by the SAME incoming
//! viewing key, so every lane of a batch takes IDENTICAL double-and-add
//! ladder steps. This module advances all lanes one step at a time, sharing
//! ONE Montgomery batch inversion per step with cheap affine formulas.
//! Honest edge over upstream's prepared path (which is already wNAF-4
//! tabled): ~1.6× per multiplication at the production batch size (N=100,
//! Apple Silicon, batch-normalized output) — the shared inversions beat the
//! table lookups, but only modestly. Degenerate lanes (identity inputs,
//! `k = 0`, `acc == ±T` collisions, `y = 0` doublings) are poison-marked;
//! the caller falls back to the per-item path for those lanes, so
//! correctness never depends on the batch.
//!
//! The kernel is OFF by default: [`set_enabled`] is the runtime toggle the
//! embedding engine flips from its config (slipstream `batch_decrypt`).
//! Byte-identical output is KAT-gated in this module's tests.

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use group::ff::{Field, PrimeField};
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::pallas;

static ENABLED: AtomicBool = AtomicBool::new(false);
// Did-it-fire counters (the graft lever's lesson: a lever without a fire
// signal is unverifiable in production — build-then-prune looked identical).
// CALLS/LANES tick on every `batch_ka_agree_dec` entry (either path);
// KERNEL_LANES ticks only when the lockstep kernel actually multiplies.
static CALLS: AtomicU64 = AtomicU64::new(0);
static LANES: AtomicU64 = AtomicU64::new(0);
static KERNEL_LANES: AtomicU64 = AtomicU64::new(0);
static NANOS: AtomicU64 = AtomicU64::new(0);

/// Runtime toggle for the batched DH kernel (default OFF = the per-item
/// path, byte-for-byte). Flipped by the embedding engine from its config;
/// resets the fire counters so each pass reads its own totals.
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
    CALLS.store(0, Ordering::Relaxed);
    LANES.store(0, Ordering::Relaxed);
    KERNEL_LANES.store(0, Ordering::Relaxed);
    NANOS.store(0, Ordering::Relaxed);
}

pub(crate) fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub(crate) fn note_call(lanes: usize) {
    CALLS.fetch_add(1, Ordering::Relaxed);
    LANES.fetch_add(lanes as u64, Ordering::Relaxed);
}

pub(crate) fn note_kernel_lanes(lanes: usize) {
    KERNEL_LANES.fetch_add(lanes as u64, Ordering::Relaxed);
}

#[cfg(feature = "std")]
pub(crate) fn note_nanos(n: u64) {
    NANOS.fetch_add(n, Ordering::Relaxed);
}

/// `(calls, lanes, kernel_lanes, nanos)` since the last [`set_enabled`].
/// `calls > 0` proves the batched seam is reached at all; `kernel_lanes > 0`
/// proves the lockstep kernel engaged (vs. the per-item fallback). `nanos`
/// is CPU-side wall accumulated inside `batch_ka_agree_dec` across all
/// threads and BOTH paths (std builds only; 0 without std) — the true
/// production DH cost, so an ON/OFF pair measures the kernel's real ratio
/// and DH's share of scan without microbenchmark assumptions.
pub fn stats() -> (u64, u64, u64, u64) {
    (
        CALLS.load(Ordering::Relaxed),
        LANES.load(Ordering::Relaxed),
        KERNEL_LANES.load(Ordering::Relaxed),
        NANOS.load(Ordering::Relaxed),
    )
}

/// Montgomery batch inversion in place. `xs` MUST contain no zeros (the
/// caller poison-replaces zeros with ONE and marks those lanes fallback).
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

/// Width-4 wNAF recode: signed odd digits, nonzero density ~1/5. Runs once
/// per (ivk, batch) — the scalar is fixed across the batch.
pub(crate) fn wnaf4(repr: &[u8; 32]) -> Vec<i8> {
    let mut k = [0u64; 5]; // one spare limb: k + 7 must not overflow
    for (i, limb) in k.iter_mut().take(4).enumerate() {
        *limb = u64::from_le_bytes(repr[i * 8..(i + 1) * 8].try_into().expect("8 bytes"));
    }
    fn is_zero(k: &[u64; 5]) -> bool {
        k.iter().all(|&x| x == 0)
    }
    fn add_small(k: &mut [u64; 5], v: u64) {
        let mut carry = v;
        for limb in k.iter_mut() {
            let (s, c) = limb.overflowing_add(carry);
            *limb = s;
            carry = u64::from(c);
            if carry == 0 {
                break;
            }
        }
    }
    fn sub_small(k: &mut [u64; 5], v: u64) {
        let mut borrow = v;
        for limb in k.iter_mut() {
            let (s, b) = limb.overflowing_sub(borrow);
            *limb = s;
            borrow = u64::from(b);
            if borrow == 0 {
                break;
            }
        }
    }
    fn shr1(k: &mut [u64; 5]) {
        for i in 0..4 {
            k[i] = (k[i] >> 1) | (k[i + 1] << 63);
        }
        k[4] >>= 1;
    }
    let mut digits = Vec::with_capacity(260);
    while !is_zero(&k) {
        if k[0] & 1 == 1 {
            let low = (k[0] & 0xF) as i8;
            let d = if low >= 8 { low - 16 } else { low };
            digits.push(d);
            if d >= 0 {
                sub_small(&mut k, d as u64);
            } else {
                add_small(&mut k, (-d) as u64);
            }
        } else {
            digits.push(0);
        }
        shr1(&mut k);
    }
    digits
}

/// `[k]·P` for every `P` in `points` — the lockstep-affine wNAF-4 ladder.
/// `None` = degenerate lane (caller falls back per-item).
pub(crate) fn batch_mul_same_scalar(
    k: &pallas::Scalar,
    points: &[pallas::Affine],
) -> Vec<Option<pallas::Affine>> {
    let n = points.len();
    if n == 0 {
        return vec![];
    }
    let repr = k.to_repr();
    let repr_bytes: &[u8] = repr.as_ref();
    let repr_arr: &[u8; 32] = repr_bytes.try_into().expect("32 bytes");
    let digits = wnaf4(repr_arr);
    if digits.is_empty() {
        return vec![None; n]; // k == 0 → identity everywhere
    }

    // Odd-multiple tables {P, 3P, 5P, 7P} per lane, built with 4 batched ops.
    let mut dead = vec![false; n];
    let mut tx = vec![vec![pallas::Base::ZERO; n]; 4];
    let mut ty = vec![vec![pallas::Base::ZERO; n]; 4];
    for (i, p) in points.iter().enumerate() {
        let coords: Option<pasta_curves::arithmetic::Coordinates<pallas::Affine>> =
            p.coordinates().into();
        match coords {
            Some(c) => {
                tx[0][i] = *c.x();
                ty[0][i] = *c.y();
            }
            None => dead[i] = true,
        }
    }
    let two = pallas::Base::from(2);
    let three = pallas::Base::from(3);
    let mut denom = vec![pallas::Base::ONE; n];

    let mut dx = vec![pallas::Base::ZERO; n];
    let mut dy = vec![pallas::Base::ZERO; n];
    for i in 0..n {
        denom[i] = if dead[i] {
            pallas::Base::ONE
        } else {
            let d = two * ty[0][i];
            if bool::from(d.is_zero()) {
                dead[i] = true;
                pallas::Base::ONE
            } else {
                d
            }
        };
    }
    batch_invert(&mut denom);
    for i in 0..n {
        if dead[i] {
            continue;
        }
        let lambda = three * tx[0][i].square() * denom[i];
        dx[i] = lambda.square() - two * tx[0][i];
        dy[i] = lambda * (tx[0][i] - dx[i]) - ty[0][i];
    }
    for j in 1..4 {
        for i in 0..n {
            denom[i] = if dead[i] {
                pallas::Base::ONE
            } else {
                let d = dx[i] - tx[j - 1][i];
                if bool::from(d.is_zero()) {
                    dead[i] = true;
                    pallas::Base::ONE
                } else {
                    d
                }
            };
        }
        batch_invert(&mut denom);
        for i in 0..n {
            if dead[i] {
                continue;
            }
            let lambda = (dy[i] - ty[j - 1][i]) * denom[i];
            let x3 = lambda.square() - tx[j - 1][i] - dx[i];
            let y3 = lambda * (tx[j - 1][i] - x3) - ty[j - 1][i];
            tx[j][i] = x3;
            ty[j][i] = y3;
        }
    }

    // Seed at the top digit (always nonzero), then the lockstep ladder.
    let top = digits.len() - 1;
    let seed = digits[top];
    let jt = ((seed.unsigned_abs() as usize) - 1) / 2;
    let mut x: Vec<pallas::Base> = (0..n).map(|i| tx[jt][i]).collect();
    let mut y: Vec<pallas::Base> = (0..n)
        .map(|i| if seed < 0 { -ty[jt][i] } else { ty[jt][i] })
        .collect();

    for pos in (0..top).rev() {
        for i in 0..n {
            denom[i] = if dead[i] {
                pallas::Base::ONE
            } else {
                let d = two * y[i];
                if bool::from(d.is_zero()) {
                    dead[i] = true;
                    pallas::Base::ONE
                } else {
                    d
                }
            };
        }
        batch_invert(&mut denom);
        for i in 0..n {
            if dead[i] {
                continue;
            }
            let lambda = three * x[i].square() * denom[i];
            let x3 = lambda.square() - two * x[i];
            let y3 = lambda * (x[i] - x3) - y[i];
            x[i] = x3;
            y[i] = y3;
        }
        let d = digits[pos];
        if d != 0 {
            let j = ((d.unsigned_abs() as usize) - 1) / 2;
            let neg = d < 0;
            for i in 0..n {
                denom[i] = if dead[i] {
                    pallas::Base::ONE
                } else {
                    let dd = tx[j][i] - x[i];
                    if bool::from(dd.is_zero()) {
                        dead[i] = true;
                        pallas::Base::ONE
                    } else {
                        dd
                    }
                };
            }
            batch_invert(&mut denom);
            for i in 0..n {
                if dead[i] {
                    continue;
                }
                let py = if neg { -ty[j][i] } else { ty[j][i] };
                let lambda = (py - y[i]) * denom[i];
                let x3 = lambda.square() - x[i] - tx[j][i];
                let y3 = lambda * (x[i] - x3) - y[i];
                x[i] = x3;
                y[i] = y3;
            }
        }
    }

    (0..n)
        .map(|i| {
            if dead[i] {
                None
            } else {
                Option::from(pallas::Affine::from_xy(x[i], y[i]))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::{Curve, Group};

    /// KAT: the kernel must be byte-identical to the curve's own scalar mult.
    #[test]
    fn kernel_matches_group_mul() {
        let base = pallas::Point::generator();
        let points: Vec<pallas::Affine> =
            (0..500u64).map(|i| (base * pallas::Scalar::from(31 + i)).to_affine()).collect();
        let k = pallas::Scalar::from(0xDEAD_BEEF_0BAD_F00Du64).square()
            + pallas::Scalar::from(17);
        let ours = batch_mul_same_scalar(&k, &points);
        for (p, o) in points.iter().zip(&ours) {
            let expected = (pallas::Point::from(*p) * k).to_affine();
            assert_eq!(o.expect("no degenerates on random points"), expected);
        }
    }

    /// End-to-end KAT through the REAL types: the batched override must equal
    /// the per-item `agree` byte-for-byte (SharedSecret comparison).
    #[test]
    fn shared_secrets_match_per_item_agree() {
        use crate::keys::{FullViewingKey, PreparedEphemeralPublicKey, PreparedIncomingViewingKey, Scope, SpendingKey};

        let sk = SpendingKey::from_bytes([7; 32]).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));

        let base = pallas::Point::generator();
        let epks: Vec<PreparedEphemeralPublicKey> = (0..200u64)
            .map(|i| {
                let p = base * pallas::Scalar::from(1_000 + i);
                PreparedEphemeralPublicKey::testing_from_point(p)
            })
            .collect();

        let k = ivk.raw_scalar();
        let bases: Vec<pallas::Affine> =
            epks.iter().map(|e| e.raw_point().to_affine()).collect();
        let batched = batch_mul_same_scalar(&k, &bases);
        for (epk, b) in epks.iter().zip(batched) {
            let per_item = epk.agree(&ivk);
            let kernel = crate::keys::SharedSecret::from_kernel_point(pallas::Point::from(
                b.expect("live"),
            ));
            assert_eq!(per_item.to_bytes(), kernel.to_bytes());
        }
    }
}
