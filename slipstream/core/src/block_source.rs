//! In-memory BlockSource adapter: serves exactly one transport Chunk to
//! upstream `scan_cached_blocks`. One chunk per scan call keeps the upstream
//! commit (one txn per call) and our memory bounded (decision D2 + plan facts).

use zcash_client_backend::{
    data_api::chain::{BlockSource, error::Error as ChainError},
    proto::compact_formats::CompactBlock,
};
use zcash_protocol::consensus::BlockHeight;

use crate::chunk::Chunk;

pub struct MemBlockSource<'a> {
    chunk: &'a Chunk,
}

impl<'a> MemBlockSource<'a> {
    pub fn new(chunk: &'a Chunk) -> Self {
        Self { chunk }
    }
}

impl BlockSource for MemBlockSource<'_> {
    type Error = std::convert::Infallible;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), ChainError<WalletErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), ChainError<WalletErrT, Self::Error>>,
    {
        let from = from_height.map(u64::from).unwrap_or(0);
        let mut served = 0usize;
        for b in &self.chunk.blocks {
            if b.height < from {
                continue;
            }
            if let Some(l) = limit
                && served >= l
            {
                break;
            }
            with_block(b.clone())?;
            served += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::Chunk;

    fn block(height: u64) -> CompactBlock {
        CompactBlock { height, hash: vec![height as u8; 32], ..Default::default() }
    }

    fn collect(src: &MemBlockSource<'_>, from: Option<u64>, limit: Option<usize>) -> Vec<u64> {
        let mut out = Vec::new();
        src.with_blocks::<_, std::convert::Infallible>(
            from.map(|h| BlockHeight::from(h as u32)),
            limit,
            |b| {
                out.push(b.height);
                Ok(())
            },
        )
        .expect("infallible");
        out
    }

    #[test]
    fn serves_all_blocks_in_order() {
        let chunk = Chunk::from_blocks(0, (100..=109).map(block).collect());
        let src = MemBlockSource::new(&chunk);
        assert_eq!(collect(&src, None, None), (100..=109).collect::<Vec<_>>());
    }

    #[test]
    fn respects_from_height_and_limit() {
        let chunk = Chunk::from_blocks(0, (100..=109).map(block).collect());
        let src = MemBlockSource::new(&chunk);
        assert_eq!(collect(&src, Some(105), Some(3)), vec![105, 106, 107]);
    }

    #[test]
    fn from_height_past_end_serves_nothing() {
        let chunk = Chunk::from_blocks(0, (100..=109).map(block).collect());
        let src = MemBlockSource::new(&chunk);
        assert!(collect(&src, Some(200), None).is_empty());
    }
}
