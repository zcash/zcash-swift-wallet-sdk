//! v0.5 Plan C — batched trial-decrypt kernel (future C1 home; mini-spec
//! `plans/2026-07-05-plan-c-batched-decrypt-minispec.md`).
//!
//! Currently contains ONLY the C0 measurement probe: what share of upstream's
//! compact batch decryption is the Diffie–Hellman scalar multiplication?
//! Gate (mini-spec §6): DH share ≥ 60% or Plan C is re-scoped/killed cheaply.

#[cfg(test)]
mod tests {
    /// C0 probe (mini-spec §6). Fabricates N compact actions with REAL Pallas
    /// ephemeral keys — mainnet shape: every epk decompresses, so every action
    /// pays the full 2-ivk DH cost. (The synthetic-chain fabricator's garbage
    /// epks would measure upstream's cheap skip path instead.)
    ///
    /// Run: `cargo test -p slipstream-core --release --lib -- --ignored decrypt_bench --nocapture`
    #[test]
    #[ignore = "bench probe; run explicitly with --release --nocapture"]
    fn decrypt_bench() {
        use std::hint::black_box;
        use std::time::Instant;

        use group::{Group, GroupEncoding};
        use orchard::keys::{PreparedIncomingViewingKey, Scope};
        use orchard::note_encryption::{CompactAction, OrchardDomain};
        use zcash_note_encryption::{Domain, EphemeralKeyBytes, ShieldedOutput};

        const N: usize = 10_000;

        // Keys: same derivation as the T10b fixture (seed [7; 32], account 0).
        let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &zcash_protocol::consensus::MAIN_NETWORK,
            &[7u8; 32],
            zip32::AccountId::ZERO,
        )
        .expect("usk from seed");
        let ufvk = usk.to_unified_full_viewing_key();
        let fvk = ufvk.orchard().expect("orchard fvk");
        let ivks: Vec<PreparedIncomingViewingKey> = [Scope::External, Scope::Internal]
            .into_iter()
            .map(|s| PreparedIncomingViewingKey::new(&fvk.to_ivk(s)))
            .collect();

        // N foreign actions with REAL (deterministic) ephemeral keys.
        let base = pasta_curves::pallas::Point::generator();
        let actions: Vec<CompactAction> = (0..N)
            .map(|i| {
                let epk = base * pasta_curves::pallas::Scalar::from(1_000 + i as u64);
                let mut nf = [0u8; 32];
                nf[..8].copy_from_slice(&(1_000_000u64 + i as u64).to_le_bytes());
                let mut cmx = [0u8; 32];
                cmx[..8].copy_from_slice(&(2_000_000u64 + i as u64).to_le_bytes());
                CompactAction::from_parts(
                    Option::from(orchard::note::Nullifier::from_bytes(&nf))
                        .expect("small-int nullifier"),
                    Option::from(orchard::note::ExtractedNoteCommitment::from_bytes(&cmx))
                        .expect("small-int cmx"),
                    EphemeralKeyBytes(epk.to_bytes()),
                    [0xC7u8; 52],
                )
            })
            .collect();
        let items: Vec<(OrchardDomain, CompactAction)> = actions
            .iter()
            .map(|a| (OrchardDomain::for_compact_action(a), a.clone()))
            .collect();

        // (i) The full upstream path — exactly what BatchRunner executes.
        let t = Instant::now();
        let results = zcash_note_encryption::batch::try_compact_note_decryption(&ivks, &items);
        let full = t.elapsed();
        assert_eq!(results.len(), N);
        assert!(
            results.iter().all(Option::is_none),
            "foreign actions must not decrypt"
        );

        // (ii) DH only: epk parse + prepare + one ka_agree per ivk — the exact
        // per-action work C1's lockstep kernel would replace.
        let t = Instant::now();
        for a in &actions {
            let epk =
                Option::from(OrchardDomain::epk(&a.ephemeral_key())).expect("real epk parses");
            let pepk = OrchardDomain::prepare_epk(epk);
            for ivk in &ivks {
                black_box(OrchardDomain::ka_agree_dec(ivk, &pepk));
            }
        }
        let dh = t.elapsed();

        let share = 100.0 * dh.as_secs_f64() / full.as_secs_f64();
        eprintln!("C0 decrypt_bench: N={N} actions x 2 scope ivks (real epks)");
        eprintln!(
            "  (i)  full upstream batch decrypt: {full:?}  ({:.1} us/action)",
            full.as_micros() as f64 / N as f64
        );
        eprintln!(
            "  (ii) DH-only (parse+prepare+2 ka_agree): {dh:?}  ({:.1} us/action)",
            dh.as_micros() as f64 / N as f64
        );
        eprintln!("  DH share of the batch-decrypt cost: {share:.1}%");
        eprintln!("  C0 gate (>= 60%): {}", if share >= 60.0 { "PASSED" } else { "FAILED" });
    }
}
