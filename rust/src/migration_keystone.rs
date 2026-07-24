//! Keystone (hardware-wallet) batch-signing UR bridge for the Orchard→Ironwood migration flow.
//!
//! Bypasses the compiled Keystone mobile SDKs (stale — single-PCZT only, no batch API) by
//! depending directly on `ur-registry`/`ur` (see the root `Cargo.toml`'s comment), mirroring the
//! pattern `chainapsis/vizor-wallet` already uses for its own Keystone integration — the same
//! pattern this module's Android sibling (`migration_keystone.rs` in
//! `zcash-android-wallet-sdk`'s `backend-lib`) already ports from. The batching primitive itself
//! is `pczt::roles::signer::batch::{BatchSignRequest, BatchSignResponse}` — not Keystone-specific;
//! these crates only provide the outer UR/CBOR/QR envelope (`ZcashSignBatch`/
//! `ZcashBatchSigResult`, registry types `"zcash-sign-batch"`/`"zcash-batch-sig-result"`).
//!
//! `BatchSignResponse`'s signatures are aligned by *position*, not by any id embedded in the wire
//! format — callers here are responsible for retaining the same PCZT ordering between
//! [`build_sign_batch_qr_parts`] and [`apply_batch_signatures`]. Both take ONE ordered
//! `&[Vec<u8>]` of unsigned PCZTs — preparation (note-split) PCZTs first, then transfer PCZTs, in
//! schedule order — the caller MUST pass the same PCZTs in the same order to build and apply.
//! This is a deliberate shape change from the Android sibling's `(split: Option<&[u8]>,
//! transfers: &[Vec<u8>])` pair: the wire order is identical (split, then transfers-in-schedule-
//! order), only the Rust-side shape is flattened to one slice, since the Swift caller already
//! holds every unsigned PCZT (from `zcashlc_migration_create_unsigned_note_split_pczts` /
//! `zcashlc_migration_create_unsigned_transfer_pczts`) as one ordered collection. The unsigned
//! PCZT bytes are passed back into `apply_batch_signatures` by that same caller rather than
//! retained as Rust-side session state — the only genuinely stateful piece here is the
//! multi-frame QR *decode* accumulation, which inherently spans multiple FFI calls (one per
//! scanned camera frame).

use std::sync::Mutex;

use pczt::roles::signer::batch::{BatchSignRequest, BatchSignResponse};
use pczt::roles::signer::{Signer, SpendAuthSignature};
use ur_registry::traits::RegistryItem;
use ur_registry::zcash::zcash_batch_sig_result::ZcashBatchSigResult;
use ur_registry::zcash::zcash_sign_batch::ZcashSignBatch;

/// Annotates every not-yet-signed Orchard/Ironwood spend action in an IO-finalized migration
/// PCZT with the account's ZIP 32 derivation path, so an external signer (Keystone) can derive
/// its own full viewing key and recognize which of its accounts a spend belongs to.
///
/// This SDK's engine call (`zcash_pool_migration_backend::engine::build_preparation_unsigned`,
/// driven by `migration.rs`'s `commit_or_resume`) never sets this metadata — it only runs the
/// shared `Creator`/`IoFinalizer` plumbing, with no `Updater` step for spend derivation (unlike
/// `zcash_client_backend::data_api::wallet::create_pczt_from_proposal`, which sets it for
/// ordinary sends). Combined with [`build_sign_batch_qr_parts`]'s batch redaction correctly
/// clearing the wire `spend_fvk` (the device is expected to derive its own), an un-annotated
/// migration PCZT gives Keystone no way to identify the account at all, which fails on-device
/// with "None of inputs belongs to the provided account".
///
/// A dummy padding spend that `IoFinalizer` already self-signed carries a `spend_auth_sig` at
/// this point and is left alone (its throwaway key needs no derivation, and this crate's
/// [`build_sign_batch_qr_parts`] clears its `spend_auth_sig` for the batch anyway); every action
/// still awaiting a real signature — a real spend, or a wallet-controlled zero-value spend
/// paired with a change output — gets the derivation.
pub(crate) fn annotate_spend_zip32_derivation(
    pczt_bytes: &[u8],
    seed_fingerprint: [u8; 32],
    coin_type: u32,
    account_index: zip32::AccountId,
) -> anyhow::Result<Vec<u8>> {
    use pczt::roles::updater::Updater;

    let derivation_path = [
        zip32::ChildIndex::hardened(32).index(),
        zip32::ChildIndex::hardened(coin_type).index(),
        zip32::ChildIndex::hardened(u32::from(account_index)).index(),
    ];

    let pczt = pczt::parse(pczt_bytes).map_err(|e| anyhow::anyhow!("parse pczt: {e:?}"))?;
    let updated = Updater::new(pczt)
        .update_orchard_with(|mut updater| {
            annotate_unsigned_actions(&mut updater, seed_fingerprint, &derivation_path)
        })
        .map_err(|e| anyhow::anyhow!("annotate orchard spend derivation: {e:?}"))?
        .update_ironwood_with(|mut updater| {
            annotate_unsigned_actions(&mut updater, seed_fingerprint, &derivation_path)
        })
        .map_err(|e| anyhow::anyhow!("annotate ironwood spend derivation: {e:?}"))?
        .finish();

    updated
        .serialize()
        .map_err(|e| anyhow::anyhow!("serialize pczt: {e:?}"))
}

fn annotate_unsigned_actions(
    updater: &mut orchard::pczt::Updater<'_>,
    seed_fingerprint: [u8; 32],
    derivation_path: &[u32],
) -> Result<(), orchard::pczt::UpdaterError> {
    let unsigned_indices: Vec<usize> = updater
        .bundle()
        .actions()
        .iter()
        .enumerate()
        .filter_map(|(index, action)| action.spend().spend_auth_sig().is_none().then_some(index))
        .collect();
    for index in unsigned_indices {
        let derivation =
            orchard::pczt::Zip32Derivation::parse(seed_fingerprint, derivation_path.to_vec())
                .expect("valid ZIP 32 derivation");
        updater.update_action_with(index, |mut action_updater| {
            action_updater.set_spend_zip32_derivation(derivation);
            Ok(())
        })?;
    }
    Ok(())
}

/// Builds the animated multi-part QR frames for a Keystone batch-signing request covering every
/// PCZT in `pczts_unsigned`, in the given order (preparation PCZTs first, then transfer PCZTs —
/// see this module's doc comment).
///
/// Every PCZT is passed through
/// [`redact_pczt_for_batch_signer`](zcash_client_backend::data_api::wallet::redact_pczt_for_batch_signer)
/// before being added to the request. The wallet's own IO-finalizer already puts `spend_auth_sig`
/// on every dummy/wallet-controlled Orchard and Ironwood spend when the unsigned PCZT is built —
/// but the Keystone batch-signing firmware rejects any batch request containing a pre-existing
/// Orchard/Ironwood `spend_auth_sig` outright ("Invalid pczt, Zcash batch request must not
/// contain Orchard spend authorization signatures"). Redacting clears those (plus the spend FVK,
/// which the device derives itself) so only what the batch signer protocol expects reaches the
/// wire; the caller's own retained, unredacted PCZT bytes are what [`apply_batch_signatures`]
/// applies the returned signatures back onto — the caller MUST pass the same PCZTs in the same
/// order to build and apply.
///
/// `request_id` is an opaque correlation token (e.g. a UUID's bytes) round-tripped by the device
/// and checked in [`decode_sign_batch_part`] to reject a scan of an unrelated/stale response.
pub(crate) fn build_sign_batch_qr_parts(
    request_id: Vec<u8>,
    pczts_unsigned: &[Vec<u8>],
    max_fragment_len: usize,
) -> anyhow::Result<Vec<String>> {
    use zcash_client_backend::data_api::wallet::redact_pczt_for_batch_signer;

    let mut pczts = Vec::with_capacity(pczts_unsigned.len());
    for bytes in pczts_unsigned {
        let parsed = pczt::parse(bytes).map_err(|e| anyhow::anyhow!("parse pczt: {e:?}"))?;
        pczts.push(redact_pczt_for_batch_signer(&parsed));
    }

    let request = BatchSignRequest::new(pczts);
    let data = request
        .serialize()
        .map_err(|e| anyhow::anyhow!("serialize batch sign request: {e:?}"))?;
    let batch = ZcashSignBatch::new(request_id, data);
    let cbor: Vec<u8> = batch
        .try_into()
        .map_err(|e| anyhow::anyhow!("cbor-encode zcash-sign-batch: {e:?}"))?;

    let mut encoder = ur::Encoder::new(
        &cbor,
        max_fragment_len,
        ZcashSignBatch::get_registry_type().get_type(),
    )
    .map_err(|e| anyhow::anyhow!("ur encoder: {e}"))?;
    let count = encoder.fragment_count();
    let mut parts = Vec::with_capacity(count);
    for _ in 0..count {
        parts.push(
            encoder
                .next_part()
                .map_err(|e| anyhow::anyhow!("ur next_part: {e}"))?
                .to_uppercase(),
        );
    }
    Ok(parts)
}

/// In-flight multi-part `zcash-batch-sig-result` scan session. `None` means no session in
/// flight — mirrors `chainapsis/vizor-wallet`'s `UR_SESSION`/`UrSession` pattern for the same
/// reason: an FFI call per scanned QR frame has nowhere else to keep fountain-decoder state.
static DECODE_SESSION: Mutex<Option<ur::Decoder>> = Mutex::new(None);

/// The result of feeding one scanned QR frame to [`decode_sign_batch_part`].
pub(crate) struct DecodePartResult {
    pub complete: bool,
    pub progress: u32,
    /// The serialized `BatchSignResponse` bytes, once `complete` — feed into
    /// [`apply_batch_signatures`].
    pub data: Option<Vec<u8>>,
    /// The signing device's raw `[major, minor, build]` firmware version, once `complete` — the
    /// `zcash-batch-sig-result` envelope's own field 3 (see keystone-sdk-rust's
    /// `ZcashBatchSigResult::get_firmware_version`), not anything recovered from the resulting
    /// signed PCZT bytes. The batch response is signatures-only (no PCZT is echoed back — see
    /// [`build_sign_batch_qr_parts`]'s doc comment), so this is the *only* place a batch-signed
    /// migration can learn the device's firmware version; a PCZT-proprietary-field scan (the
    /// mechanism the single-transaction Keystone sign flow's firmware stamp relies on) always
    /// comes back empty here, since [`apply_batch_signatures`] reconstructs the "signed" PCZT from
    /// the caller's own retained unsigned bytes plus these signatures, never from device-returned
    /// PCZT bytes.
    pub firmware_version: Option<[u8; 3]>,
}

/// Discards any in-flight multi-part scan session. Callers should invoke this on scan-screen
/// entry so a new attempt always starts from a clean slate regardless of how a previous attempt
/// ended (cancel, back button, mid-stream error).
pub(crate) fn reset_sign_batch_decoder() {
    if let Ok(mut guard) = DECODE_SESSION.lock() {
        *guard = None;
    }
}

/// Feeds one scanned QR frame into the active (or a freshly started) decode session, pinned to
/// the `"zcash-batch-sig-result"` UR type. `expected_request_id` must match the decoded
/// `ZcashBatchSigResult`'s own request id once complete, or this returns an error (a scan of an
/// unrelated/stale response) instead of silently accepting it.
pub(crate) fn decode_sign_batch_part(
    part: &str,
    expected_request_id: &[u8],
) -> anyhow::Result<DecodePartResult> {
    let part_lower = part.to_lowercase();
    let mut guard = DECODE_SESSION
        .lock()
        .map_err(|_| anyhow::anyhow!("decode session lock poisoned"))?;

    if guard.is_none() {
        let (kind, cbor) =
            ur::decode(&part_lower).map_err(|e| anyhow::anyhow!("ur decode: {e}"))?;
        match kind {
            ur::ur::Kind::SinglePart => return finish_decode(cbor, expected_request_id),
            ur::ur::Kind::MultiPart => {
                let mut decoder = ur::Decoder::default();
                decoder
                    .receive(&part_lower)
                    .map_err(|e| anyhow::anyhow!("ur receive: {e}"))?;
                let progress = decoder.progress();
                *guard = Some(decoder);
                return Ok(DecodePartResult {
                    complete: false,
                    progress: progress as u32,
                    data: None,
                    firmware_version: None,
                });
            }
        }
    }

    if let Err(e) = guard.as_mut().unwrap().receive(&part_lower) {
        *guard = None;
        return Err(anyhow::anyhow!("ur receive: {e}"));
    }

    if guard.as_ref().unwrap().complete() {
        let message = guard
            .as_mut()
            .unwrap()
            .message()
            .map_err(|e| anyhow::anyhow!("ur message: {e}"))?;
        *guard = None;
        let cbor = message.ok_or_else(|| anyhow::anyhow!("decoder complete but no message"))?;
        return finish_decode(cbor, expected_request_id);
    }

    let progress = guard.as_ref().unwrap().progress();
    Ok(DecodePartResult {
        complete: false,
        progress: progress as u32,
        data: None,
        firmware_version: None,
    })
}

fn finish_decode(cbor: Vec<u8>, expected_request_id: &[u8]) -> anyhow::Result<DecodePartResult> {
    let result = ZcashBatchSigResult::try_from(cbor)
        .map_err(|e| anyhow::anyhow!("cbor-decode zcash-batch-sig-result: {e:?}"))?;
    if result.get_request_id() != expected_request_id {
        return Err(anyhow::anyhow!(
            "zcash-batch-sig-result request id does not match the outstanding sign request"
        ));
    }
    Ok(DecodePartResult {
        complete: true,
        progress: 100,
        data: Some(result.get_data().to_vec()),
        firmware_version: Some(*result.get_firmware_version()),
    })
}

/// Applies a decoded `BatchSignResponse` back to the retained unsigned PCZTs — in the exact order
/// they were passed to [`build_sign_batch_qr_parts`] — producing signed-but-unproven PCZT bytes
/// for each, in that same order. These are the same shape
/// `zcashlc_migration_store_signed_note_split_pczts`/`zcashlc_migration_store_signed_schedule_pczts`
/// already expect from the in-process-signing composition — no other change needed there.
///
/// Returns an error if the response's signature-set count doesn't match the number of PCZTs
/// passed in — the caller MUST pass the same PCZTs in the same order to build and apply.
pub(crate) fn apply_batch_signatures(
    pczts_unsigned: &[Vec<u8>],
    batch_sign_response: &[u8],
) -> anyhow::Result<Vec<Vec<u8>>> {
    let response = BatchSignResponse::parse(batch_sign_response)
        .map_err(|e| anyhow::anyhow!("parse batch sign response: {e:?}"))?;
    let signatures = response.signatures();
    if signatures.len() != pczts_unsigned.len() {
        return Err(anyhow::anyhow!(
            "batch sign response has {} signature set(s), expected {} (one per PCZT passed to \
             apply_batch_signatures, in the same order passed to build_sign_batch_qr_parts)",
            signatures.len(),
            pczts_unsigned.len(),
        ));
    }

    pczts_unsigned
        .iter()
        .zip(signatures)
        .map(|(bytes, sigs)| apply_signatures_to_one(bytes, sigs))
        .collect()
}

fn apply_signatures_to_one(
    unsigned_bytes: &[u8],
    sigs: &[SpendAuthSignature],
) -> anyhow::Result<Vec<u8>> {
    let pczt =
        pczt::parse(unsigned_bytes).map_err(|e| anyhow::anyhow!("parse unsigned pczt: {e:?}"))?;
    let mut signer = Signer::new(pczt).map_err(|e| anyhow::anyhow!("signer init: {e:?}"))?;
    for sig in sigs {
        signer
            .apply_orchard_spend_auth_signature(sig)
            .map_err(|e| anyhow::anyhow!("apply spend auth signature: {e:?}"))?;
    }
    signer
        .finish()
        .serialize()
        .map_err(|e| anyhow::anyhow!("serialize signed pczt: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    use orchard::value::NoteValue;
    use pczt::roles::creator::Creator;
    use pczt::roles::io_finalizer::IoFinalizer;
    use rand::rngs::OsRng;
    use shardtree::ShardTree;
    use shardtree::store::memory::MemoryShardStore;
    use ur_registry::zcash::zcash_sign_batch::ZcashSignBatch;
    use zcash_note_encryption::try_note_decryption;
    use zcash_primitives::transaction::builder::{BuildConfig, Builder, PcztResult};
    use zcash_primitives::transaction::fees::zip317;
    use zcash_protocol::consensus::{BlockHeight, Network};
    use zcash_protocol::memo::{Memo, MemoBytes};
    use zcash_protocol::value::Zatoshis;

    /// Builds a real, IO-finalized single-Orchard-pool PCZT (one spend, one output),
    /// mirroring the shape the real migration pipeline hands to
    /// [`build_sign_batch_qr_parts`]: since the transaction has fewer real actions than
    /// Orchard's default padding minimum, the Orchard builder inserts a dummy padding
    /// action, and `IoFinalizer` self-signs that dummy spend (see `pczt::roles::io_finalizer`'s
    /// "dummy spends will have been signed" note) — producing exactly the kind of
    /// pre-existing `spend_auth_sig` the Keystone batch firmware rejects.
    fn build_single_pool_orchard_pczt() -> Vec<u8> {
        let mut rng = OsRng;
        let sk = SpendingKey::from_zip32_seed(&[11u8; 32], 1, zip32::AccountId::ZERO)
            .expect("valid Orchard ZIP 32 spending key");
        let fvk = FullViewingKey::from(&sk);
        let ivk = fvk.to_ivk(Scope::Internal);
        let ovk = fvk.to_ovk(Scope::Internal);
        let recipient = fvk.address_at(0u32, Scope::Internal);

        // Pretend we already received a note to spend.
        let value = NoteValue::from_raw(1_000_000);
        let note = {
            let bundle_version = orchard::bundle::BundleVersion::orchard_v2();
            let mut builder = orchard::builder::Builder::new(
                orchard::builder::BundleType::DEFAULT,
                bundle_version,
                bundle_version.default_flags(),
                orchard::Anchor::empty_tree(),
            )
            .expect("orchard builder");
            builder
                .add_output(None, recipient, value, Memo::Empty.encode().into_bytes())
                .expect("add output");
            let (bundle, meta) = builder
                .build::<i64>(&mut rng)
                .expect("build orchard bundle")
                .expect("non-empty bundle");
            let action = bundle
                .actions()
                .get(meta.output_action_index(0).expect("output action index"))
                .expect("action present");
            let domain = orchard::note_encryption::OrchardDomain::for_action(action);
            let (note, _, _) =
                try_note_decryption(&domain, &ivk.prepare(), action).expect("decrypt own output");
            note
        };

        // Single-leaf tree for the spend's witness/anchor.
        let (anchor, merkle_path) = {
            let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
            let leaf = orchard::tree::MerkleHashOrchard::from_cmx(&cmx);
            let mut tree = ShardTree::<_, 32, 16>::new(
                MemoryShardStore::<orchard::tree::MerkleHashOrchard, u32>::empty(),
                100,
            );
            tree.append(leaf, incrementalmerkletree::Retention::Marked)
                .expect("append leaf");
            tree.checkpoint(9_999_999).expect("checkpoint");
            let position = 0.into();
            let merkle_path = tree
                .witness_at_checkpoint_depth(position, 0)
                .expect("witness lookup")
                .expect("witness present");
            let anchor = merkle_path.root(leaf);
            (anchor.into(), merkle_path.into())
        };

        // Well past TestNetwork's NU5 (Orchard) activation, comfortably before NU6.
        let target_height = BlockHeight::from_u32(1_900_000);
        let mut builder: Builder<Network, ()> = Builder::new(
            Network::TestNetwork,
            target_height,
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(anchor),
                ironwood_anchor: None,
                orchard_bundle_type: orchard::builder::BundleType::DEFAULT,
                ironwood_bundle_type: orchard::builder::BundleType::DEFAULT,
            },
        );
        builder
            .add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path)
            .expect("add spend");
        builder
            .add_orchard_output::<zip317::FeeRule>(
                Some(ovk),
                recipient,
                // 1_000_000 in - 10_000 ZIP-317 fee (2 grace actions x 5_000 marginal fee).
                Zatoshis::const_from_u64(990_000),
                MemoBytes::empty(),
            )
            .expect("add output");

        let PcztResult { pczt_parts, .. } = builder
            .build_for_pczt(OsRng, &zip317::FeeRule::standard())
            .expect("build_for_pczt");

        let base = Creator::build_from_parts(pczt_parts).expect("creator");
        let base = IoFinalizer::new(base).finalize_io().expect("io finalize");
        base.serialize().expect("serialize")
    }

    #[test]
    fn build_sign_batch_qr_parts_strips_preexisting_orchard_spend_auth_sig() {
        let unsigned = build_single_pool_orchard_pczt();

        // Sanity-check the premise: the IO-finalized PCZT already carries a dummy
        // spend_auth_sig before redaction — this is what regressed without the fix.
        let parsed = pczt::parse(&unsigned).expect("parse base pczt");
        assert!(
            parsed
                .orchard()
                .actions()
                .iter()
                .any(|action| action.spend().spend_auth_sig().is_some()),
            "test setup must produce a pre-signed dummy Orchard spend",
        );

        let parts = build_sign_batch_qr_parts(
            b"test-request-id".to_vec(),
            &[unsigned.clone()],
            // Large enough that the whole request fits in a single UR frame.
            1_000_000,
        )
        .expect("build_sign_batch_qr_parts");
        assert_eq!(parts.len(), 1, "expected a single QR frame");

        // `ur::Encoder` always emits the indexed multi-part wire format, even for a
        // single fragment, so decode via `ur::Decoder` rather than assuming
        // `ur::ur::Kind::SinglePart`.
        let mut decoder = ur::Decoder::default();
        decoder
            .receive(&parts[0].to_lowercase())
            .expect("ur receive");
        assert!(
            decoder.complete(),
            "single fragment should complete decoding"
        );
        let cbor = decoder
            .message()
            .expect("ur message")
            .expect("decoder complete but no message");
        let batch = ZcashSignBatch::try_from(cbor).expect("cbor-decode zcash-sign-batch");
        let request = BatchSignRequest::parse(batch.get_data()).expect("parse batch sign request");

        assert_eq!(request.pczts().len(), 1);
        for action in request.pczts()[0].orchard().actions() {
            assert!(
                action.spend().spend_auth_sig().is_none(),
                "batch request must not contain a pre-existing Orchard spend_auth_sig",
            );
        }
    }

    #[test]
    fn annotate_spend_zip32_derivation_sets_derivation_only_on_unsigned_actions() {
        let unsigned = build_single_pool_orchard_pczt();
        let base = pczt::parse(&unsigned).expect("parse base pczt");
        // Sanity-check the premise: neither action carries a derivation path yet.
        for action in base.orchard().actions() {
            assert!(
                !format!("{:?}", action.spend()).contains("zip32_derivation: Some"),
                "test setup must start without any spend zip32_derivation set",
            );
        }

        let seed_fingerprint = [42u8; 32];
        let coin_type = 1; // testnet
        let account_index = zip32::AccountId::ZERO;
        let annotated =
            annotate_spend_zip32_derivation(&unsigned, seed_fingerprint, coin_type, account_index)
                .expect("annotate_spend_zip32_derivation");

        let parsed = pczt::parse(&annotated).expect("parse annotated pczt");
        let actions = parsed.orchard().actions();
        assert_eq!(actions.len(), base.orchard().actions().len());

        let mut unsigned_count = 0;
        let mut signed_count = 0;
        for (base_action, action) in base.orchard().actions().iter().zip(actions.iter()) {
            let has_derivation = format!("{:?}", action.spend()).contains("zip32_derivation: Some");
            if base_action.spend().spend_auth_sig().is_some() {
                // Already-signed (dummy) spends are left alone.
                signed_count += 1;
                assert!(
                    !has_derivation,
                    "an already-signed dummy spend must not get a derivation path",
                );
            } else {
                unsigned_count += 1;
                assert!(
                    has_derivation,
                    "a real, still-unsigned spend must get a derivation path",
                );
            }
        }
        assert_eq!(
            unsigned_count, 1,
            "expected exactly one real unsigned spend"
        );
        assert_eq!(signed_count, 1, "expected exactly one dummy signed spend");
    }

    /// New vs. the Android original: pins the single-array shape's count-mismatch check.
    /// `BatchSignResponse::new` is cheap to construct directly (no device fixture needed) — an
    /// empty signature-set list is already a mismatch against any non-empty PCZT slice.
    #[test]
    fn apply_batch_signatures_returns_error_on_signature_count_mismatch() {
        let unsigned = build_single_pool_orchard_pczt();
        let response_bytes = BatchSignResponse::new(Vec::new())
            .serialize()
            .expect("serialize empty batch sign response");

        let err = apply_batch_signatures(&[unsigned], &response_bytes)
            .expect_err("signature-set count mismatch must error");
        let message = err.to_string();
        assert!(
            message.contains("expected 1"),
            "error should report the expected PCZT count: {message}"
        );
    }

    /// Feeds `parts` to [`decode_sign_batch_part`] in order, cycling back to the start if more
    /// are needed, until a call reports completion or errors. Mirrors a real scan loop, which
    /// keeps feeding scanned camera frames — the same single frame repeatedly, for a
    /// single-fragment response — until the decoder reports done, rather than assuming a fixed
    /// call count.
    fn feed_parts_until_complete(
        parts: &[String],
        expected_request_id: &[u8],
    ) -> anyhow::Result<DecodePartResult> {
        // Comfortably more than enough attempts for any fragment count exercised here.
        let attempts = parts.len().max(1) * 4;
        for i in 0..attempts {
            let result = decode_sign_batch_part(&parts[i % parts.len()], expected_request_id)?;
            if result.complete {
                return Ok(result);
            }
        }
        panic!("decode_sign_batch_part did not complete after {attempts} attempts");
    }

    /// New vs. the Android original: `decode_sign_batch_part` is this SDK's own addition, so it
    /// has no upstream test to mirror. Pins its two device-independent guarantees without a real
    /// Keystone: the `expected_request_id` mismatch check, and the firmware/data passthrough on
    /// success. Constructs a `ZcashBatchSigResult` directly (its `new` is public — see
    /// keystone-sdk-rust's `zcash_batch_sig_result.rs`), CBOR- and UR-encodes it exactly the way
    /// a real device response arrives on the wire (the encode-side mirror of
    /// [`build_sign_batch_qr_parts_strips_preexisting_orchard_spend_auth_sig`]'s decode step),
    /// then feeds the resulting frame(s) through the production decode path twice — once under
    /// the wrong `expected_request_id`, once under the right one.
    #[test]
    fn decode_sign_batch_part_checks_request_id_and_returns_data_and_firmware() {
        let request_id = b"test-request-id".to_vec();
        let data = b"pretend-serialized-batch-sign-response".to_vec();
        let firmware_version = [4u8, 5, 6];

        let result = ZcashBatchSigResult::new(request_id.clone(), data.clone(), firmware_version);
        let cbor: Vec<u8> = result
            .try_into()
            .expect("cbor-encode zcash-batch-sig-result");

        // `ur::Encoder` always emits the indexed multi-part wire format, even for a single
        // fragment (see `build_sign_batch_qr_parts_strips_preexisting_orchard_spend_auth_sig`'s
        // comment) — `decode_sign_batch_part` is exercised exactly as a real scan would, whatever
        // the fragment count.
        let mut encoder = ur::Encoder::new(
            &cbor,
            // Large enough that the whole result fits in a single UR frame.
            1_000_000,
            ZcashBatchSigResult::get_registry_type().get_type(),
        )
        .expect("ur encoder");
        let count = encoder.fragment_count();
        let mut parts = Vec::with_capacity(count);
        for _ in 0..count {
            parts.push(encoder.next_part().expect("ur next_part").to_uppercase());
        }

        // A scan of the full response under the WRONG expected request id must be rejected, not
        // silently accepted.
        reset_sign_batch_decoder();
        let mismatch = feed_parts_until_complete(&parts, b"some-other-request-id");
        let err = match mismatch {
            Ok(_) => panic!("wrong expected_request_id must error"),
            Err(e) => e,
        };
        assert!(
            err.to_string()
                .contains("does not match the outstanding sign request"),
            "unexpected error message: {err}"
        );

        // The decode session is a global static (see `DECODE_SESSION`'s doc comment) — a fresh
        // scan must not see any state left over from the mismatched-id scan above.
        reset_sign_batch_decoder();
        let decoded = feed_parts_until_complete(&parts, &request_id)
            .expect("decode_sign_batch_part with the right request id must succeed");
        assert!(decoded.complete, "final part must report completion");
        assert_eq!(
            decoded.data.expect("data present on completion"),
            data,
            "decoded data must round-trip exactly"
        );
        assert_eq!(
            decoded
                .firmware_version
                .expect("firmware version present on completion"),
            firmware_version,
            "firmware version must pass through exactly"
        );
    }
}
