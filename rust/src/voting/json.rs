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
#[allow(dead_code)]
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
#[allow(dead_code)]
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

/// JSON-serializable `voting::vote::VoteCommit`.
///
/// The helper-share payloads are deliberately absent: they are wire data owned
/// by `zcash_voting`, produced by `zcashlc_voting_recover_wire_json` once the
/// confirmed vote-commitment-tree position is known. Commit-time payloads are
/// provisional and must never be sent to helper servers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonVoteCommit {
    pub proposal_id: u32,
    pub van_nullifier: Vec<u8>,
    pub vote_authority_note_new: Vec<u8>,
    pub vote_commitment: Vec<u8>,
    pub proof: Vec<u8>,
    pub anchor_height: u32,
    pub r_vpk: Vec<u8>,
    pub vote_auth_sig: Vec<u8>,
    pub enc_shares: Vec<voting::WireEncryptedShare>,
}

impl From<voting::vote::VoteCommit> for JsonVoteCommit {
    fn from(c: voting::vote::VoteCommit) -> Self {
        Self {
            proposal_id: c.proposal_id,
            van_nullifier: c.van_nullifier.to_vec(),
            vote_authority_note_new: c.vote_authority_note_new.to_vec(),
            vote_commitment: c.vote_commitment.to_vec(),
            proof: c.proof,
            anchor_height: c.anchor_height,
            r_vpk: c.r_vpk.to_vec(),
            vote_auth_sig: c.vote_auth_sig.to_vec(),
            enc_shares: c.encrypted_shares,
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
    pub seed_fingerprint: Vec<u8>,
}
