use serde::{Deserialize, Serialize};
use zcash_voting as voting;

/// JSON-serializable `NoteInfo`.
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

/// JSON-serializable `DelegationPirPrecomputeResult`.
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
