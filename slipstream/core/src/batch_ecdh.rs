//! v0.5 Plan C — batched trial-decrypt kernel (mini-spec
//! `plans/2026-07-05-plan-c-batched-decrypt-minispec.md`).
//!
//! C0 (done): the measurement probe — DH = 92.4% of upstream's compact batch
//! decryption cost (M4, 10k real-epk actions × 2 scope ivks).
//!
//! C1 (this file): the lockstep-affine batched DH kernel. Trial decryption
//! multiplies MANY ephemeral keys by the SAME ivk scalar, so every lane of a
//! batch takes IDENTICAL double-and-add ladder steps — the exact shape
//! batch_sinsemilla exploits: advance all lanes one step at a time, share ONE
//! Montgomery batch inversion per step, use cheap affine formulas instead of
//! projective ones. Degenerate lanes (zero denominators: point at infinity,
//! acc == ±P collisions) are poison-marked and the caller falls back to the
//! scalar path — correctness never depends on the batch.
//!
//! The kernel is curve-level (pasta_curves only, no orchard API): the fork
//! wiring step transplants it behind a `Domain::batch_ka_agree` seam
//! (zcash_note_encryption fork + orchard override). Until then the module is
//! test-gated — KAT + kernel bench live here.

use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::group::Curve;
use pasta_curves::group::ff::{Field, PrimeField};
use pasta_curves::pallas;

use crate::batch_sinsemilla::batch_invert;

/// Width-4 wNAF recode. The scalar is FIXED across the batch, so this runs
/// once per (ivk, batch) — digits are `0` or odd `±1,±3,±5,±7`, nonzero
/// density ~1/5 (vs ~1/2 raw bits), cutting the ladder's add steps ~60%.
/// Index = bit position (LSB first); the top digit is always nonzero.
fn wnaf4(repr: &[u8; 32]) -> Vec<i8> {
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
            let low = (k[0] & 0xF) as i8; // k mod 16
            let d = if low >= 8 { low - 16 } else { low }; // signed odd residue
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

/// `[k]·P` for every `P` in `points` — lockstep-affine wNAF-4 ladder with one
/// shared Montgomery inversion per ladder step. The scalar is the SAME for
/// every lane, so every lane takes IDENTICAL steps: recode once, build the
/// odd-multiple table {P,3P,5P,7P} per lane with 4 batched ops, then ~255
/// batched doubles + ~51 batched adds. `None` = degenerate lane (the caller
/// computes that lane with the scalar path). Identity inputs are degenerate
/// by definition (affine coordinates cannot represent them).
pub(crate) fn batch_mul_same_scalar(
    k: &pallas::Scalar,
    points: &[pallas::Affine],
) -> Vec<Option<pallas::Affine>> {
    let n = points.len();
    if n == 0 {
        return vec![];
    }
    let repr = k.to_repr(); // 32 bytes, little-endian
    let repr_bytes: &[u8] = repr.as_ref();
    let repr_arr: &[u8; 32] = repr_bytes.try_into().expect("32 bytes");
    let digits = wnaf4(repr_arr);
    if digits.is_empty() {
        // k == 0: [0]·P is the identity for every lane — all degenerate.
        return vec![None; n];
    }

    // ── Lane state + the odd-multiple tables, built with 4 batched steps ────
    let mut dead = vec![false; n];
    // tbl[j][i] = (2j+1)·P_i as affine (j = 0..3 → P, 3P, 5P, 7P).
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
            None => dead[i] = true, // point at infinity
        }
    }
    let two = pallas::Base::from(2);
    let three = pallas::Base::from(3);
    let mut denom = vec![pallas::Base::ONE; n];

    // 2P (scratch), then 3P = 2P+P, 5P = 3P+2P, 7P = 5P+2P — all batched.
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
        // tbl[j] = tbl[j-1] + 2P
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

    // ── Seed at the top digit (always nonzero), then the lockstep ladder ────
    let top = digits.len() - 1;
    let seed = digits[top];
    let jt = ((seed.unsigned_abs() as usize) - 1) / 2;
    let mut x: Vec<pallas::Base> = (0..n).map(|i| tx[jt][i]).collect();
    let mut y: Vec<pallas::Base> = (0..n)
        .map(|i| if seed < 0 { -ty[jt][i] } else { ty[jt][i] })
        .collect();

    for pos in (0..top).rev() {
        // DOUBLE every lane: λ = 3x² / 2y.
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
        // ADD ±(2j+1)·P on a nonzero digit: λ = (Ty − y) / (Tx − x).
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
                        dead[i] = true; // acc == ±T: double/infinity degenerate
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
    use pasta_curves::group::prime::PrimeCurveAffine;
    use pasta_curves::group::{Group, GroupEncoding};

    fn synth_points(n: usize, salt: u64) -> Vec<pallas::Affine> {
        let base = pallas::Point::generator();
        (0..n)
            .map(|i| (base * pallas::Scalar::from(salt + i as u64)).to_affine())
            .collect()
    }

    /// KAT: the kernel must be byte-identical to pasta's own scalar mult for
    /// every lane. 1k in debug, keeps the default suite fast.
    #[test]
    fn kernel_matches_pasta_mul_1k() {
        let k = pallas::Scalar::from(0xDEAD_BEEF_1234_5678u64).square(); // widen past 64 bits
        let points = synth_points(1_000, 7);
        let ours = batch_mul_same_scalar(&k, &points);
        for (p, o) in points.iter().zip(&ours) {
            let expected = (pallas::Point::from(*p) * k).to_affine();
            assert_eq!(o.expect("no degenerates on random points"), expected);
        }
    }

    /// Release-scale KAT (the batch_sinsemilla convention):
    /// `cargo test -p slipstream-core --release --lib -- --ignored kernel_matches_pasta_mul_100k`
    #[test]
    #[ignore = "heavy: 100k lanes; run explicitly with --release"]
    fn kernel_matches_pasta_mul_100k() {
        let k = pallas::Scalar::from(0x1357_9BDF_2468_ACE0u64).square()
            + pallas::Scalar::from(3);
        let points = synth_points(100_000, 11);
        let ours = batch_mul_same_scalar(&k, &points);
        for (p, o) in points.iter().zip(&ours) {
            let expected = (pallas::Point::from(*p) * k).to_affine();
            assert_eq!(o.expect("no degenerates on random points"), expected);
        }
    }

    /// Degenerates: k = 0 and the identity input must be poison-marked, never wrong.
    #[test]
    fn degenerates_are_poisoned_not_wrong() {
        let points = synth_points(4, 23);
        assert!(
            batch_mul_same_scalar(&pallas::Scalar::ZERO, &points).iter().all(Option::is_none),
            "k = 0 has no affine representation — every lane degenerate"
        );
        let with_identity = vec![pallas::Affine::identity(), points[1]];
        let out = batch_mul_same_scalar(&pallas::Scalar::from(5), &with_identity);
        assert!(out[0].is_none(), "identity input is degenerate");
        assert!(out[1].is_some(), "live lanes are unaffected by dead neighbors");
    }

    /// C1 kernel bench: the lockstep kernel vs the exact per-mult work the
    /// production baseline pays (prepared-key `ka_agree_dec`).
    /// `cargo test -p slipstream-core --release --lib -- --ignored dh_kernel_bench --nocapture`
    #[test]
    #[ignore = "bench probe; run explicitly with --release --nocapture"]
    fn dh_kernel_bench() {
        use orchard::keys::{PreparedIncomingViewingKey, Scope};
        use orchard::note_encryption::OrchardDomain;
        use std::hint::black_box;
        use std::time::Instant;
        use zcash_note_encryption::Domain;

        const N: usize = 10_000;

        // The production ivk (prepared) — and the raw pallas work it hides.
        let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &zcash_protocol::consensus::MAIN_NETWORK,
            &[7u8; 32],
            zip32::AccountId::ZERO,
        )
        .expect("usk");
        let fvk = usk.to_unified_full_viewing_key().orchard().expect("orchard fvk").clone();
        let pivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));

        let points = synth_points(N, 1_000);

        // (a) upstream per-item path: prepare_epk + ka_agree_dec per point —
        // byte-for-byte the work inside batch::try_compact_note_decryption.
        let t = Instant::now();
        for p in &points {
            let epk = Option::from(OrchardDomain::epk(&zcash_note_encryption::EphemeralKeyBytes(
                p.to_bytes(),
            )))
            .expect("valid epk");
            let pepk = OrchardDomain::prepare_epk(epk);
            black_box(OrchardDomain::ka_agree_dec(&pivk, &pepk));
        }
        let upstream = t.elapsed();

        // (b) the lockstep kernel with a same-width scalar (the real ivk scalar
        // is not exposed by orchard's API — the fork wiring reaches it from
        // inside; a random full-width scalar is arithmetically equivalent work).
        let k = pallas::Scalar::from(0xFEED_F00D_CAFE_BABEu64).square()
            + pallas::Scalar::from(0x0123_4567_89AB_CDEFu64);
        let t = Instant::now();
        let out = batch_mul_same_scalar(&k, &points);
        let kernel = t.elapsed();
        assert!(out.iter().all(Option::is_some));
        black_box(out);

        let ratio = upstream.as_secs_f64() / kernel.as_secs_f64();
        eprintln!("C1 dh_kernel_bench: N={N} lanes");
        eprintln!(
            "  (a) upstream prepared ka_agree_dec: {upstream:?}  ({:.1} us/mult)",
            upstream.as_micros() as f64 / N as f64
        );
        eprintln!(
            "  (b) lockstep-affine kernel:         {kernel:?}  ({:.1} us/mult)",
            kernel.as_micros() as f64 / N as f64
        );
        eprintln!("  kernel ratio: {ratio:.2}x");
    }
}
