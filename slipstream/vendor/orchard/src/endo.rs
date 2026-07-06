//! [slipstream fork] GLV endomorphism multiplication for trial-decrypt DH
//! (v0.5 C2 — the per-item path, unlike C1's batched kernel).
//!
//! Pallas carries the cube-root endomorphism φ(x, y) = (ζ_p·x, y) with
//! φ(P) = λ·P for λ = `Scalar::ZETA`, ζ_p = `Base::ZETA` (pairing verified
//! on-curve). A one-time GLV decomposition splits the 255-bit ivk scalar
//! into two signed ≤127-bit halves k = k1 + k2·λ (mod q), so
//! `k·P = k1·P + k2·φ(P)` runs as a Straus ladder with SHARED doublings:
//! ~128 doublings + ~52 window-4 adds instead of ~255 + ~51 — roughly 1.7×
//! fewer group operations per multiplication, allocation-light and
//! cache-resident (the C1 postmortem's requirements for surviving real
//! scan-thread concurrency).
//!
//! OFF by default; [`set_enabled`] is the engine's runtime toggle
//! (slipstream `endo_mul`). Byte-identical output is KAT-gated below, and
//! the GLV constants are re-verified from scratch in-crate
//! (`decompose_reconstructs`): wrong constants cannot pass the tests.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ff::{PrimeField, WithSmallOrderMulGroup};
use group::{Curve, Group, prime::PrimeCurveAffine};
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::pallas;

static ENABLED: AtomicBool = AtomicBool::new(false);
static CALLS: AtomicU64 = AtomicU64::new(0);

/// Runtime toggle (default OFF = upstream's prepared wNAF walk verbatim).
/// Resets the fire counter so each pass reads its own total.
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
    CALLS.store(0, Ordering::Relaxed);
}

pub(crate) fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub(crate) fn note_call() {
    CALLS.fetch_add(1, Ordering::Relaxed);
}

/// Multiplications served by the endo path since the last [`set_enabled`].
pub fn calls() -> u64 {
    CALLS.load(Ordering::Relaxed)
}

// ── GLV constants (derived + 300k-verified offline 2026-07-06; re-proven by
// `decompose_reconstructs` below, and the φ↔λ pairing by `endo_map_is_lambda`).
// Short lattice basis for {(a, b) : a + b·λ ≡ 0 (mod q)}:
//   v1 = (V1A, −V1B_NEG), v2 = (V2A, V2B)
const V1A: u128 = 0x49e69d1640f049157fcae1c700000001;
const V1B_NEG: u128 = 0x49e69d1640a899538cb1279300000000;
const V2A: u128 = 0x49e69d1640a899538cb1279300000000;
const V2B: u128 = 0x93cd3a2c8198e2690c7c095a00000001;
// Babai rounding: g1 = round(2^384·v2.b / q), g2 = round(2^384·(−v1.b) / q).
const G1: [u64; 5] = [
    0x111f686111afc293,
    0xc35fbd4d086862e0,
    0x31f0256800000002,
    0x4f34e8b2066389a4,
    0x2,
];
const G2: [u64; 5] = [
    0x4a95a2d972171db4,
    0x61afdea68480fa55,
    0x32c49e4bffffffff,
    0x279a745902a2654e,
    0x1,
];

/// `round((g · k) / 2^384)` for a 5-limb `g` and 4-limb `k` — the Babai
/// coefficient. Fits u128 (≤ ~128 bits by construction).
fn round_mul_shift(g: &[u64; 5], k: &[u64; 4]) -> u128 {
    let mut prod = [0u64; 9];
    for (i, &gi) in g.iter().enumerate() {
        let mut carry = 0u128;
        for (j, &kj) in k.iter().enumerate() {
            let t = u128::from(gi) * u128::from(kj) + u128::from(prod[i + j]) + carry;
            prod[i + j] = t as u64;
            carry = t >> 64;
        }
        prod[i + 4] = prod[i + 4].wrapping_add(carry as u64);
    }
    // Bits ≥ 384 live in limbs 6..; round on bit 383 (top bit of limb 5).
    let round = prod[5] >> 63;
    (u128::from(prod[6]) | (u128::from(prod[7]) << 64)).wrapping_add(u128::from(round))
}

/// 256-bit two's-complement helpers for the signed half extraction.
fn mul_u128(a: u128, b: u128) -> [u64; 4] {
    let (a0, a1) = (a as u64, (a >> 64) as u64);
    let (b0, b1) = (b as u64, (b >> 64) as u64);
    let mut out = [0u64; 4];
    let mut acc = |i: usize, v: u128| {
        let mut idx = i;
        let mut carry = v;
        while carry != 0 {
            let t = u128::from(out[idx]) + (carry & u128::from(u64::MAX));
            out[idx] = t as u64;
            carry = (carry >> 64) + (t >> 64);
            idx += 1;
        }
    };
    acc(0, u128::from(a0) * u128::from(b0));
    acc(1, u128::from(a0) * u128::from(b1));
    acc(1, u128::from(a1) * u128::from(b0));
    acc(2, u128::from(a1) * u128::from(b1));
    out
}

fn sub256(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d, b1) = a[i].overflowing_sub(b[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        out[i] = d;
        borrow = u64::from(b1) + u64::from(b2);
    }
    out
}

/// Interpret a 256-bit two's-complement value with |x| < 2^128 as (sign, |x|).
fn signed_halves(x: [u64; 4]) -> (bool, u128) {
    if x[3] >> 63 == 0 {
        debug_assert!(x[2] == 0 && x[3] == 0, "positive half exceeds 128 bits");
        (false, u128::from(x[0]) | (u128::from(x[1]) << 64))
    } else {
        // negate: !x + 1
        let mut n = [!x[0], !x[1], !x[2], !x[3]];
        let mut carry = 1u64;
        for limb in &mut n {
            let (v, c) = limb.overflowing_add(carry);
            *limb = v;
            carry = u64::from(c);
            if carry == 0 {
                break;
            }
        }
        debug_assert!(n[2] == 0 && n[3] == 0, "negative half exceeds 128 bits");
        (true, u128::from(n[0]) | (u128::from(n[1]) << 64))
    }
}

/// GLV split: `k = k1 + k2·λ (mod q)` with |k1|, |k2| ≤ 2^127.
pub(crate) fn decompose(k: &pallas::Scalar) -> ((bool, u128), (bool, u128)) {
    let repr = k.to_repr();
    let bytes: &[u8; 32] = repr.as_ref().try_into().expect("32-byte repr");
    let mut kl = [0u64; 4];
    for (i, limb) in kl.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().expect("8 bytes"));
    }
    let c1 = round_mul_shift(&G1, &kl);
    let c2 = round_mul_shift(&G2, &kl);
    // k1 = k − c1·V1A − c2·V2A   (two's complement over 256 bits)
    let k1 = sub256(sub256(kl, mul_u128(c1, V1A)), mul_u128(c2, V2A));
    // k2 = c1·V1B_NEG − c2·V2B   (v1.b = −V1B_NEG, v2.b = +V2B)
    let k2 = sub256(mul_u128(c1, V1B_NEG), mul_u128(c2, V2B));
    (signed_halves(k1), signed_halves(k2))
}

/// φ(P) on affine coordinates: (ζ_p·x, y). Identity maps to identity.
fn endo_affine(p: &pallas::Affine) -> pallas::Affine {
    let coords = p.coordinates();
    if bool::from(coords.is_none()) {
        return pallas::Affine::identity();
    }
    let c = coords.unwrap();
    pallas::Affine::from_xy(pallas::Base::ZETA * c.x(), *c.y()).unwrap()
}

/// `k·P` via the GLV split + Straus shared-doubling ladder (window-4 wNAF
/// on both halves; odd-multiple tables of P and φ(P), one shared batch
/// normalization). Byte-identical to `P * k` — KAT-gated.
pub fn mul_endo(p: &pallas::Point, k: &pallas::Scalar) -> pallas::Point {
    if bool::from(p.is_identity()) {
        return pallas::Point::identity();
    }
    let ((s1, a1), (s2, a2)) = decompose(k);
    if a1 == 0 && a2 == 0 {
        return pallas::Point::identity();
    }

    // Odd multiples {1,3,5,7}·P (projective), one batch normalization.
    let two_p = p.double();
    let mut odds = [*p; 4];
    for i in 1..4 {
        odds[i] = odds[i - 1] + two_p;
    }
    let mut t1 = [pallas::Affine::identity(); 4];
    pallas::Point::batch_normalize(&odds, &mut t1);
    let mut t2 = [pallas::Affine::identity(); 4];
    for (dst, src) in t2.iter_mut().zip(t1.iter()) {
        *dst = endo_affine(src);
    }

    let (d1, l1) = wnaf_digits(a1);
    let (d2, l2) = wnaf_digits(a2);
    let len = l1.max(l2);

    let mut acc = pallas::Point::identity();
    for i in (0..len).rev() {
        acc = acc.double();
        let d = if i < l1 { d1[i] } else { 0 };
        if d != 0 {
            let mut a = t1[(d.unsigned_abs() / 2) as usize];
            if (d < 0) ^ s1 {
                a = -a;
            }
            acc += a;
        }
        let d = if i < l2 { d2[i] } else { 0 };
        if d != 0 {
            let mut a = t2[(d.unsigned_abs() / 2) as usize];
            if (d < 0) ^ s2 {
                a = -a;
            }
            acc += a;
        }
    }
    acc
}

/// Width-4 wNAF of a u128 magnitude — allocation-free (per-call in the hot
/// per-item path, unlike the once-per-batch C1 recoder). A ≤2^127 magnitude
/// yields at most 129 digits; the array is sized with headroom.
fn wnaf_digits(a: u128) -> ([i8; 132], usize) {
    debug_assert!(a >> 127 == 0, "magnitude must be <= 127 bits");
    let mut digits = [0i8; 132];
    let mut n = 0;
    let mut k = a;
    while k != 0 {
        if k & 1 == 1 {
            let low = (k & 0xF) as i8;
            let d = if low >= 8 { low - 16 } else { low };
            digits[n] = d;
            if d >= 0 {
                k -= d as u128;
            } else {
                k += (-d) as u128;
            }
        }
        n += 1;
        k >>= 1;
    }
    (digits, n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;

    /// Deterministic "random-ish" full-width scalars (the fork's KAT pattern).
    fn scalars(n: u64) -> impl Iterator<Item = pallas::Scalar> {
        (0..n).map(|i| {
            (pallas::Scalar::from(0x9E37_79B9_7F4A_7C15u64 + i).square()
                + pallas::Scalar::from(0x0123_4567_89AB_CDEFu64))
            .square()
                + pallas::Scalar::from(i)
        })
    }

    /// The φ↔λ pairing on the real curve: (ζ_p·x, y) == λ·P.
    #[test]
    fn endo_map_is_lambda() {
        let g = pallas::Point::generator();
        for k in scalars(64) {
            let p = (g * k).to_affine();
            let via_map = endo_affine(&p);
            let via_mul = (pallas::Point::from(p) * pallas::Scalar::ZETA).to_affine();
            assert_eq!(via_map, via_mul, "phi(P) must equal ZETA_scalar * P");
        }
    }

    /// The algebraic gate: k1 + k2·λ ≡ k (mod q) with both halves ≤ 2^127,
    /// for full-width scalars AND the edge cases. Wrong GLV constants cannot
    /// pass this.
    #[test]
    fn decompose_reconstructs() {
        let edges = [
            pallas::Scalar::ZERO,
            pallas::Scalar::ONE,
            -pallas::Scalar::ONE,
            pallas::Scalar::ZETA,
            pallas::Scalar::ZETA.square(),
            pallas::Scalar::from(u64::MAX),
        ];
        for k in edges.into_iter().chain(scalars(2_000)) {
            let ((s1, a1), (s2, a2)) = decompose(&k);
            assert!(a1 >> 127 == 0 && a2 >> 127 == 0, "halves must be ≤127 bits");
            let half = |s: bool, a: u128| {
                let v = pallas::Scalar::from_u128(a);
                if s { -v } else { v }
            };
            let rec = half(s1, a1) + half(s2, a2) * pallas::Scalar::ZETA;
            assert_eq!(rec, k, "k1 + k2*lambda must reconstruct k");
        }
    }

    /// KAT: byte-identical to the curve's own scalar multiplication.
    #[test]
    fn mul_endo_matches_group_mul() {
        let g = pallas::Point::generator();
        let n = if cfg!(debug_assertions) { 500 } else { 4_000 };
        for (i, k) in scalars(n).enumerate() {
            let base = g * pallas::Scalar::from(31 + i as u64);
            assert_eq!(mul_endo(&base, &k), base * k, "lane {i}");
        }
        // Edges: zero scalar, identity base, ±1, λ.
        assert_eq!(mul_endo(&g, &pallas::Scalar::ZERO), pallas::Point::identity());
        assert_eq!(mul_endo(&pallas::Point::identity(), &pallas::Scalar::from(7)), pallas::Point::identity());
        assert_eq!(mul_endo(&g, &pallas::Scalar::ONE), g);
        assert_eq!(mul_endo(&g, &-pallas::Scalar::ONE), -g);
        assert_eq!(mul_endo(&g, &pallas::Scalar::ZETA), g * pallas::Scalar::ZETA);
    }
}
