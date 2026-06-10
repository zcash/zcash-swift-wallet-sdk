//! Hash-chain continuity across ordered blocks/chunks. Detects server gaps,
//! reordering bugs, and (later) reorg seams before anything reaches the scanner.

use zcash_client_backend::proto::compact_formats::CompactBlock;

use crate::error::SlipstreamError;

/// Carries the verification frontier between chunks.
#[derive(Clone, Debug, Default)]
pub struct Continuity {
    /// Hash of the last verified block (None at the very start of a fetch).
    pub last_hash: Option<Vec<u8>>,
    pub last_height: Option<u64>,
}

impl Continuity {
    /// Verifies heights are consecutive and prev_hash links hold; advances self.
    pub fn verify_blocks(&mut self, blocks: &[CompactBlock]) -> Result<(), SlipstreamError> {
        for b in blocks {
            if let Some(h) = self.last_height
                && b.height != h + 1
            {
                return Err(SlipstreamError::Discontinuity {
                    at: b.height as u32,
                    detail: format!("expected height {}, got {}", h + 1, b.height),
                });
            }
            // NOTE: lightwalletd populates prev_hash in GetBlockRange responses;
            // empty prev_hash is tolerated for synthetic/first blocks only. A server
            // stripping prev_hash would degrade this check to heights-only.
            if let Some(prev) = &self.last_hash
                && !b.prev_hash.is_empty()
                && &b.prev_hash != prev
            {
                return Err(SlipstreamError::Discontinuity {
                    at: b.height as u32,
                    detail: "prev-hash mismatch".into(),
                });
            }
            self.last_hash = Some(b.hash.clone());
            self.last_height = Some(b.height);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linked(from: u64, count: u64) -> Vec<CompactBlock> {
        (from..from + count)
            .map(|h| CompactBlock {
                height: h,
                hash: vec![h as u8; 32],
                prev_hash: if h == from { vec![] } else { vec![(h - 1) as u8; 32] },
                ..Default::default()
            })
            .collect()
    }

    #[test]
    fn accepts_linked_blocks_across_two_calls() {
        let mut c = Continuity::default();
        let all = linked(100, 10);
        c.verify_blocks(&all[..5]).expect("first half");
        // Second half must link to the first (its first prev_hash = hash of 104).
        let mut second = all[5..].to_vec();
        second[0].prev_hash = vec![104u8 as u8; 32];
        c.verify_blocks(&second).expect("second half");
        assert_eq!(c.last_height, Some(109));
    }

    #[test]
    fn rejects_height_gap() {
        let mut c = Continuity::default();
        c.verify_blocks(&linked(100, 3)).expect("ok");
        let err = c.verify_blocks(&linked(105, 1)).unwrap_err();
        assert!(matches!(err, SlipstreamError::Discontinuity { at: 105, .. }));
    }

    #[test]
    fn rejects_prev_hash_mismatch() {
        let mut c = Continuity::default();
        c.verify_blocks(&linked(100, 2)).expect("ok");
        let mut bad = linked(102, 1);
        bad[0].prev_hash = vec![0xEE; 32];
        let err = c.verify_blocks(&bad).unwrap_err();
        assert!(matches!(err, SlipstreamError::Discontinuity { at: 102, .. }));
    }
}
