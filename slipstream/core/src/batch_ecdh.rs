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

/// `[k]·P` for every `P` in `points` — lockstep-affine double-and-add with one
/// shared Montgomery inversion per ladder step. `None` = degenerate lane (the
/// caller computes that lane with the scalar path). Identity inputs are
/// degenerate by definition (affine coordinates cannot represent them).
pub(crate) fn batch_mul_same_scalar(
    k: &pallas::Scalar,
    points: &[pallas::Affine],
) -> Vec<Option<pallas::Affine>> {
    let n = points.len();
    if n == 0 {
        return vec![];
    }

    // Scalar bits, most-significant first, from the top set bit. The scalar is
    // the SAME for every lane — this is what makes the ladder lockstep.
    let repr = k.to_repr(); // 32 bytes, little-endian
    let repr_bytes: &[u8] = repr.as_ref();
    let bit = |i: usize| (repr_bytes[i / 8] >> (i % 8)) & 1 == 1;
    let top = match (0..256).rev().find(|&i| bit(i)) {
        Some(t) => t,
        // k == 0: [0]·P is the identity for every lane — all degenerate.
        None => return vec![None; n],
    };

    // Lane state: affine accumulator, seeded acc = P at the top set bit.
    let mut x = Vec::with_capacity(n);
    let mut y = Vec::with_capacity(n);
    let mut dead = vec![false; n];
    for (i, p) in points.iter().enumerate() {
        let coords: Option<pasta_curves::arithmetic::Coordinates<pallas::Affine>> =
            p.coordinates().into();
        match coords {
            Some(c) => {
                x.push(*c.x());
                y.push(*c.y());
            }
            None => {
                // Point at infinity — degenerate input.
                x.push(pallas::Base::ZERO);
                y.push(pallas::Base::ZERO);
                dead[i] = true;
            }
        }
    }

    let mut denom = vec![pallas::Base::ONE; n];
    let two = pallas::Base::from(2);
    let three = pallas::Base::from(3);

    for step in (0..top).rev() {
        // ── DOUBLE every lane: λ = 3x² / 2y ─────────────────────────────────
        for i in 0..n {
            if dead[i] {
                denom[i] = pallas::Base::ONE;
                continue;
            }
            let d = two * y[i];
            if bool::from(d.is_zero()) {
                dead[i] = true; // y = 0 ⇒ doubling lands on infinity
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
            let lambda = three * x[i].square() * denom[i];
            let x3 = lambda.square() - two * x[i];
            let y3 = lambda * (x[i] - x3) - y[i];
            x[i] = x3;
            y[i] = y3;
        }

        // ── conditional ADD of the base point: λ = (Py − y) / (Px − x) ──────
        if bit(step) {
            for i in 0..n {
                if dead[i] {
                    denom[i] = pallas::Base::ONE;
                    continue;
                }
                let c = points[i].coordinates().expect("live lanes have affine bases");
                let d = *c.x() - x[i];
                if bool::from(d.is_zero()) {
                    dead[i] = true; // acc == ±P: doubling case or infinity result
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
                let c = points[i].coordinates().expect("live lanes have affine bases");
                let (px, py) = (*c.x(), *c.y());
                let lambda = (py - y[i]) * denom[i];
                let x3 = lambda.square() - x[i] - px;
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
