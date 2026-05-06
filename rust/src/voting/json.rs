use serde::{Deserialize, Serialize};
use zcash_voting as voting;

// =============================================================================
// Serde-compatible types for JSON serialization across the FFI boundary
// =============================================================================

/// JSON-serializable NoteInfo.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonNoteInfo {
    pub commitment: Vec<u8>,
    pub nullifier: Vec<u8>,
    pub value: u64,
    pub position: u64,
    pub diversifier: Vec<u8>,
    pub rho: Vec<u8>,
    pub rseed: Vec<u8>,
    pub scope: u32,
    pub ufvk_str: String,
}

impl From<JsonNoteInfo> for voting::NoteInfo {
    fn from(n: JsonNoteInfo) -> Self {
        Self {
            commitment: n.commitment,
            nullifier: n.nullifier,
            value: n.value,
            position: n.position,
            diversifier: n.diversifier,
            rho: n.rho,
            rseed: n.rseed,
            scope: n.scope,
            ufvk_str: n.ufvk_str,
        }
    }
}

impl From<voting::NoteInfo> for JsonNoteInfo {
    fn from(n: voting::NoteInfo) -> Self {
        Self {
            commitment: n.commitment,
            nullifier: n.nullifier,
            value: n.value,
            position: n.position,
            diversifier: n.diversifier,
            rho: n.rho,
            rseed: n.rseed,
            scope: n.scope,
            ufvk_str: n.ufvk_str,
        }
    }
}

/// JSON-serializable VotingPczt.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonVotingPczt {
    pub pczt_bytes: Vec<u8>,
    pub rk: Vec<u8>,
    pub alpha: Vec<u8>,
    pub nf_signed: Vec<u8>,
    pub cmx_new: Vec<u8>,
    pub gov_nullifiers: Vec<Vec<u8>>,
    pub van: Vec<u8>,
    pub van_comm_rand: Vec<u8>,
    pub dummy_nullifiers: Vec<Vec<u8>>,
    pub rho_signed: Vec<u8>,
    pub padded_cmx: Vec<Vec<u8>>,
    pub rseed_signed: Vec<u8>,
    pub rseed_output: Vec<u8>,
    pub action_bytes: Vec<u8>,
    pub action_index: u32,
    /// padded_note_secrets: list of [rho, rseed] pairs
    pub padded_note_secrets: Vec<Vec<Vec<u8>>>,
    pub pczt_sighash: Vec<u8>,
}

impl From<voting::GovernancePczt> for JsonVotingPczt {
    fn from(g: voting::GovernancePczt) -> Self {
        Self {
            pczt_bytes: g.pczt_bytes,
            rk: g.rk,
            alpha: g.alpha,
            nf_signed: g.nf_signed,
            cmx_new: g.cmx_new,
            gov_nullifiers: g.gov_nullifiers,
            van: g.van,
            van_comm_rand: g.van_comm_rand,
            dummy_nullifiers: g.dummy_nullifiers,
            rho_signed: g.rho_signed,
            padded_cmx: g.padded_cmx,
            rseed_signed: g.rseed_signed,
            rseed_output: g.rseed_output,
            action_bytes: g.action_bytes,
            action_index: g.action_index as u32,
            padded_note_secrets: g
                .padded_note_secrets
                .into_iter()
                .map(|(rho, rseed)| vec![rho, rseed])
                .collect(),
            pczt_sighash: g.pczt_sighash,
        }
    }
}

/// JSON-serializable WitnessData.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonWitnessData {
    pub note_commitment: Vec<u8>,
    pub position: u64,
    pub root: Vec<u8>,
    pub auth_path: Vec<Vec<u8>>,
}

impl From<voting::WitnessData> for JsonWitnessData {
    fn from(w: voting::WitnessData) -> Self {
        Self {
            note_commitment: w.note_commitment,
            position: w.position,
            root: w.root,
            auth_path: w.auth_path,
        }
    }
}

impl From<JsonWitnessData> for voting::WitnessData {
    fn from(w: JsonWitnessData) -> Self {
        Self {
            note_commitment: w.note_commitment,
            position: w.position,
            root: w.root,
            auth_path: w.auth_path,
        }
    }
}

/// JSON-serializable DelegationProofResult.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonDelegationProofResult {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<Vec<u8>>,
    pub nf_signed: Vec<u8>,
    pub cmx_new: Vec<u8>,
    pub gov_nullifiers: Vec<Vec<u8>>,
    pub van_comm: Vec<u8>,
    pub rk: Vec<u8>,
}

impl From<voting::DelegationProofResult> for JsonDelegationProofResult {
    fn from(r: voting::DelegationProofResult) -> Self {
        Self {
            proof: r.proof,
            public_inputs: r.public_inputs,
            nf_signed: r.nf_signed,
            cmx_new: r.cmx_new,
            gov_nullifiers: r.gov_nullifiers,
            van_comm: r.van_comm,
            rk: r.rk,
        }
    }
}

/// JSON-serializable DelegationPirPrecomputeResult.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonDelegationPirPrecomputeResult {
    pub cached_count: u32,
    pub fetched_count: u32,
}

impl From<voting::DelegationPirPrecomputeResult> for JsonDelegationPirPrecomputeResult {
    fn from(r: voting::DelegationPirPrecomputeResult) -> Self {
        Self {
            cached_count: r.cached_count,
            fetched_count: r.fetched_count,
        }
    }
}

/// JSON-serializable DelegationSubmission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonDelegationSubmission {
    pub rk: Vec<u8>,
    pub spend_auth_sig: Vec<u8>,
    pub sighash: Vec<u8>,
    pub nf_signed: Vec<u8>,
    pub cmx_new: Vec<u8>,
    pub gov_comm: Vec<u8>,
    pub gov_nullifiers: Vec<Vec<u8>>,
    pub proof: Vec<u8>,
    pub vote_round_id: String,
}

impl From<voting::DelegationSubmissionData> for JsonDelegationSubmission {
    fn from(d: voting::DelegationSubmissionData) -> Self {
        Self {
            rk: d.rk,
            spend_auth_sig: d.spend_auth_sig,
            sighash: d.sighash,
            nf_signed: d.nf_signed,
            cmx_new: d.cmx_new,
            gov_comm: d.gov_comm,
            gov_nullifiers: d.gov_nullifiers,
            proof: d.proof,
            vote_round_id: d.vote_round_id,
        }
    }
}

/// Wire-safe encrypted share that omits secret fields (plaintext_value, randomness).
/// Used in SharePayload which is sent to the helper server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonWireEncryptedShare {
    pub c1: Vec<u8>,
    pub c2: Vec<u8>,
    pub share_index: u32,
}

impl From<voting::EncryptedShare> for JsonWireEncryptedShare {
    fn from(s: voting::EncryptedShare) -> Self {
        Self {
            c1: s.c1,
            c2: s.c2,
            share_index: s.share_index,
        }
    }
}

impl From<JsonWireEncryptedShare> for voting::WireEncryptedShare {
    fn from(s: JsonWireEncryptedShare) -> Self {
        Self {
            c1: s.c1,
            c2: s.c2,
            share_index: s.share_index,
        }
    }
}

/// JSON-serializable VoteCommitmentBundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonVoteCommitmentBundle {
    pub van_nullifier: Vec<u8>,
    pub vote_authority_note_new: Vec<u8>,
    pub vote_commitment: Vec<u8>,
    pub proposal_id: u32,
    pub proof: Vec<u8>,
    pub enc_shares: Vec<JsonWireEncryptedShare>,
    pub anchor_height: u32,
    pub vote_round_id: String,
    pub shares_hash: Vec<u8>,
    pub share_blinds: Vec<Vec<u8>>,
    pub share_comms: Vec<Vec<u8>>,
    pub r_vpk_bytes: Vec<u8>,
    pub alpha_v: Vec<u8>,
}

impl From<voting::VoteCommitmentBundle> for JsonVoteCommitmentBundle {
    fn from(b: voting::VoteCommitmentBundle) -> Self {
        Self {
            van_nullifier: b.van_nullifier,
            vote_authority_note_new: b.vote_authority_note_new,
            vote_commitment: b.vote_commitment,
            proposal_id: b.proposal_id,
            proof: b.proof,
            enc_shares: b.enc_shares.into_iter().map(Into::into).collect(),
            anchor_height: b.anchor_height,
            vote_round_id: b.vote_round_id,
            shares_hash: b.shares_hash,
            share_blinds: b.share_blinds,
            share_comms: b.share_comms,
            r_vpk_bytes: b.r_vpk_bytes,
            alpha_v: b.alpha_v,
        }
    }
}

impl From<JsonVoteCommitmentBundle> for voting::VoteCommitmentBundle {
    fn from(b: JsonVoteCommitmentBundle) -> Self {
        Self {
            van_nullifier: b.van_nullifier,
            vote_authority_note_new: b.vote_authority_note_new,
            vote_commitment: b.vote_commitment,
            proposal_id: b.proposal_id,
            proof: b.proof,
            // enc_shares with secrets are not sent across FFI; wire shares are
            // passed separately to build_share_payloads, so this is unused.
            enc_shares: Vec::new(),
            anchor_height: b.anchor_height,
            vote_round_id: b.vote_round_id,
            shares_hash: b.shares_hash,
            share_blinds: b.share_blinds,
            share_comms: b.share_comms,
            r_vpk_bytes: b.r_vpk_bytes,
            alpha_v: b.alpha_v,
        }
    }
}

/// JSON-serializable SharePayload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonSharePayload {
    pub shares_hash: Vec<u8>,
    pub proposal_id: u32,
    pub vote_decision: u32,
    pub enc_share: JsonWireEncryptedShare,
    pub tree_position: u64,
    pub all_enc_shares: Vec<JsonWireEncryptedShare>,
    pub share_comms: Vec<Vec<u8>>,
    pub primary_blind: Vec<u8>,
}

impl From<voting::SharePayload> for JsonSharePayload {
    fn from(p: voting::SharePayload) -> Self {
        Self {
            shares_hash: p.shares_hash,
            proposal_id: p.proposal_id,
            vote_decision: p.vote_decision,
            enc_share: JsonWireEncryptedShare {
                c1: p.enc_share.c1,
                c2: p.enc_share.c2,
                share_index: p.enc_share.share_index,
            },
            tree_position: p.tree_position,
            all_enc_shares: p
                .all_enc_shares
                .into_iter()
                .map(|s| JsonWireEncryptedShare {
                    c1: s.c1,
                    c2: s.c2,
                    share_index: s.share_index,
                })
                .collect(),
            share_comms: p.share_comms,
            primary_blind: p.primary_blind,
        }
    }
}

/// JSON-serializable CastVoteSignature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonCastVoteSignature {
    pub vote_auth_sig: Vec<u8>,
}

impl From<voting::CastVoteSignature> for JsonCastVoteSignature {
    fn from(s: voting::CastVoteSignature) -> Self {
        Self {
            vote_auth_sig: s.vote_auth_sig,
        }
    }
}

/// JSON-serializable DelegationInputs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonDelegationInputs {
    pub fvk_bytes: Vec<u8>,
    pub g_d_new_x: Vec<u8>,
    pub pk_d_new_x: Vec<u8>,
    pub hotkey_raw_address: Vec<u8>,
    pub hotkey_public_key: Vec<u8>,
    pub hotkey_address: String,
    pub seed_fingerprint: Vec<u8>,
}

/// JSON-serializable VanWitness.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonVanWitness {
    pub auth_path: Vec<Vec<u8>>,
    pub position: u32,
    pub anchor_height: u32,
}

impl From<voting::tree_sync::VanWitness> for JsonVanWitness {
    fn from(w: voting::tree_sync::VanWitness) -> Self {
        Self {
            auth_path: w.auth_path.iter().map(|h| h.to_vec()).collect(),
            position: w.position,
            anchor_height: w.anchor_height,
        }
    }
}
