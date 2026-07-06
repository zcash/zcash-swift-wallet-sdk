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

    /// Shared wiring A/B harness: FULL upstream batch decryption with a fork
    /// lever ENABLED vs DISABLED must be identical — hits, misses, ivk
    /// indices, and the REAL owned note found either way. (The toggles are
    /// process-global; concurrent tests taking a lever path stay sound —
    /// each is KAT-gated byte-identical.)
    fn wired_decrypt_ab(set_lever: impl Fn(bool)) {
        use orchard::keys::{PreparedIncomingViewingKey, Scope};
        use orchard::note_encryption::{CompactAction, OrchardDomain};
        use zcash_note_encryption::EphemeralKeyBytes;

        let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &zcash_protocol::consensus::MAIN_NETWORK,
            &[7u8; 32],
            zip32::AccountId::ZERO,
        )
        .expect("usk");
        let ufvk = usk.to_unified_full_viewing_key();
        let fvk = ufvk.orchard().expect("orchard fvk");
        let ivks: Vec<PreparedIncomingViewingKey> = [Scope::External, Scope::Internal]
            .into_iter()
            .map(|s| PreparedIncomingViewingKey::new(&fvk.to_ivk(s)))
            .collect();

        // 500 foreign real-epk actions + ONE real owned action in the middle.
        let owned = crate::oracle::testkit::owned_orchard_action(&ufvk, 250_000, 9);
        let mut actions: Vec<CompactAction> = Vec::new();
        for i in 0..500u64 {
            if i == 250 {
                actions.push(CompactAction::from_parts(
                    Option::from(orchard::note::Nullifier::from_bytes(&owned.nullifier))
                        .expect("owned nf"),
                    Option::from(orchard::note::ExtractedNoteCommitment::from_bytes(&owned.cmx))
                        .expect("owned cmx"),
                    EphemeralKeyBytes(owned.ephemeral_key),
                    owned.ciphertext.as_slice().try_into().expect("52 bytes"),
                ));
                continue;
            }
            let epk = pallas::Point::generator() * pallas::Scalar::from(50_000 + i);
            let mut nf = [0u8; 32];
            nf[..8].copy_from_slice(&(3_000_000u64 + i).to_le_bytes());
            let mut cmx = [0u8; 32];
            cmx[..8].copy_from_slice(&(4_000_000u64 + i).to_le_bytes());
            actions.push(CompactAction::from_parts(
                Option::from(orchard::note::Nullifier::from_bytes(&nf)).expect("nf"),
                Option::from(orchard::note::ExtractedNoteCommitment::from_bytes(&cmx))
                    .expect("cmx"),
                EphemeralKeyBytes(epk.to_bytes()),
                [0xC7u8; 52],
            ));
        }
        let items: Vec<(OrchardDomain, CompactAction)> = actions
            .iter()
            .map(|a| (OrchardDomain::for_compact_action(a), a.clone()))
            .collect();

        set_lever(false);
        let off = zcash_note_encryption::batch::try_compact_note_decryption(&ivks, &items);
        set_lever(true);
        let on = zcash_note_encryption::batch::try_compact_note_decryption(&ivks, &items);
        set_lever(false); // restore the default

        assert_eq!(off.len(), on.len());
        for (i, (a, b)) in off.iter().zip(&on).enumerate() {
            match (a, b) {
                (None, None) => {}
                (Some(((na, _), ia)), Some(((nb, _), ib))) => {
                    assert_eq!(ia, ib, "ivk index differs at {i}");
                    assert_eq!(na.value(), nb.value(), "note value differs at {i}");
                }
                _ => panic!("hit/miss pattern differs at action {i}"),
            }
        }
        assert!(off[250].is_some(), "the owned action must decrypt (lever off)");
        assert!(on[250].is_some(), "the owned action must decrypt (lever on)");
    }

    /// C1 wired A/B: full batch decryption ON vs OFF is identical (incl. a
    /// real owned note) with the lockstep kernel as the lever.
    #[test]
    fn wired_batch_decrypt_matches_per_item() {
        wired_decrypt_ab(orchard::batch_dh::set_enabled);
    }

    /// C2 wired A/B: same harness with the GLV endomorphism path as the lever.
    #[test]
    fn wired_endo_mul_matches_per_item() {
        wired_decrypt_ab(orchard::endo::set_enabled);
    }

    /// C2 honest per-item bench THROUGH THE REAL SEAM: `ka_agree_dec` with the
    /// endo lever off vs on, prepared keys built once (production shape).
    /// `cargo test -p slipstream-core --release --lib -- --ignored endo_bench --nocapture`
    #[test]
    #[ignore = "bench probe; run explicitly with --release --nocapture"]
    fn endo_bench() {
        use orchard::keys::{PreparedIncomingViewingKey, Scope};
        use orchard::note_encryption::OrchardDomain;
        use std::hint::black_box;
        use std::time::Instant;
        use zcash_note_encryption::Domain;

        let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &zcash_protocol::consensus::MAIN_NETWORK,
            &[7u8; 32],
            zip32::AccountId::ZERO,
        )
        .expect("usk");
        let fvk = usk.to_unified_full_viewing_key().orchard().expect("orchard fvk").clone();
        let pivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));

        let n = 2_000usize;
        let points = synth_points(n, 1_000);
        let pepks: Vec<_> = points
            .iter()
            .map(|p| {
                let epk = Option::from(OrchardDomain::epk(
                    &zcash_note_encryption::EphemeralKeyBytes(p.to_bytes()),
                ))
                .expect("valid epk");
                OrchardDomain::prepare_epk(epk)
            })
            .collect();

        orchard::endo::set_enabled(false);
        let t = Instant::now();
        for pepk in &pepks {
            black_box(OrchardDomain::ka_agree_dec(&pivk, pepk));
        }
        let upstream = t.elapsed();

        orchard::endo::set_enabled(true);
        let t = Instant::now();
        for pepk in &pepks {
            black_box(OrchardDomain::ka_agree_dec(&pivk, pepk));
        }
        let endo = t.elapsed();
        orchard::endo::set_enabled(false);

        eprintln!(
            "C2 endo bench N={n}: upstream {:.1} us/mult | endo {:.1} us/mult | ratio {:.2}x",
            upstream.as_micros() as f64 / n as f64,
            endo.as_micros() as f64 / n as f64,
            upstream.as_secs_f64() / endo.as_secs_f64(),
        );
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

        // HONEST comparison (v2 — the first version bundled prepare_epk + TWO
        // ka_agree calls into the baseline while timing ONE kernel mult, and
        // upstream's prepared path is already wNAF-tabled with one table
        // serving both scope ivks — the wired device A/B exposed it):
        //   (a) prepare ONCE per point (amortized out), time ONLY the mult;
        //   (b) the kernel in its WIRED shape — per-ivk call, projective
        //       inputs (to_affine cost included), at the given batch size.
        for &n in &[100usize, 1_000, N] {
            let points = synth_points(n, 1_000);
            let pepks: Vec<_> = points
                .iter()
                .map(|p| {
                    let epk = Option::from(OrchardDomain::epk(
                        &zcash_note_encryption::EphemeralKeyBytes(p.to_bytes()),
                    ))
                    .expect("valid epk");
                    OrchardDomain::prepare_epk(epk)
                })
                .collect();

            // (a) the true baseline: one prepared mult per lane.
            let t = Instant::now();
            for pepk in &pepks {
                black_box(OrchardDomain::ka_agree_dec(&pivk, pepk));
            }
            let upstream = t.elapsed();

            // (b) the kernel as WIRED: projective in (to_affine inside the
            // measurement, per-point — the current override's shape).
            let k = pallas::Scalar::from(0xFEED_F00D_CAFE_BABEu64).square()
                + pallas::Scalar::from(0x0123_4567_89AB_CDEFu64);
            let projective: Vec<pallas::Point> =
                points.iter().map(|p| pallas::Point::from(*p)).collect();
            let t = Instant::now();
            let affine: Vec<pallas::Affine> =
                projective.iter().map(|p| p.to_affine()).collect();
            let out = batch_mul_same_scalar(&k, &affine);
            let kernel_wired = t.elapsed();
            assert!(out.iter().all(Option::is_some));
            black_box(out);

            // (c) the kernel with batch-normalized inputs (the fix).
            let t = Instant::now();
            let mut affine2 = vec![pallas::Affine::identity(); n];
            pallas::Point::batch_normalize(&projective, &mut affine2);
            let out = batch_mul_same_scalar(&k, &affine2);
            let kernel_fixed = t.elapsed();
            black_box(out);

            eprintln!(
                "C1 honest bench N={n}: upstream {:.1} us/mult | wired {:.1} ({:.2}x) | batch-normalized {:.1} ({:.2}x)",
                upstream.as_micros() as f64 / n as f64,
                kernel_wired.as_micros() as f64 / n as f64,
                upstream.as_secs_f64() / kernel_wired.as_secs_f64(),
                kernel_fixed.as_micros() as f64 / n as f64,
                upstream.as_secs_f64() / kernel_fixed.as_secs_f64(),
            );
        }
    }
}
