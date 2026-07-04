//! v0.4 Plan A — the shard accumulator (spec §4, plan Task 6). Pure state
//! machine: commitments stream in position order; each 2^16-position shard is
//! BUFFERED until either an owned note appears in it (eager flush → build now,
//! witness timing identical to v0.3.6) or it closes note-free (the caller asks
//! the graft verdict). Two structural safety rules, decided 2026-07-04:
//!
//! 1. `finish()` always Builds — the open (range-end / tip) shard never grafts,
//!    so by pass end the tree contains every scanned position (frontier and
//!    anchor semantics exactly today's; straddling shards build, not graft).
//! 2. The caller enables buffering only on Historic-priority ranges (Task 7):
//!    the ChainTip range runs today's passthrough path verbatim, so mid-restore
//!    summary/anchor reads (which reference tip-side checkpoints) are untouched.

use incrementalmerkletree::Retention;
use zcash_protocol::consensus::BlockHeight;

/// Shard height shared by both pools.
const SHARD_BITS: u32 = 16;

fn shard_of(position: u64) -> u64 {
    position >> SHARD_BITS
}

/// One accumulated commitment: (absolute position, hash, retention).
pub(crate) type AccRow<H> = (u64, H, Retention<BlockHeight>);

/// What the caller must do with a slice of the stream, in emission order.
#[derive(Debug, PartialEq)]
pub(crate) enum FeedAction<H> {
    /// Feed these rows through today's build path NOW (passthrough shard, eager
    /// note flush, or `finish`). Positions are contiguous within the action.
    Build(Vec<AccRow<H>>),
    /// A shard closed note-free: ask the graft verdict for `shard_index`.
    /// `rows` is the COMPLETE row set seen for it — on a missing server root
    /// the caller builds these exact rows (no DB re-read).
    CloseCleanShard { shard_index: u64, rows: Vec<AccRow<H>> },
    /// Persist these NEW rows into the buffer table this chunk (the shard is
    /// still open and note-free; earlier rows were emitted in earlier feeds).
    Buffer(Vec<AccRow<H>>),
}

struct OpenShard<H> {
    index: u64,
    /// Full row set while buffering (bounded: ≤ 2^16 rows ≈ 2.5 MB/pool).
    rows: Vec<AccRow<H>>,
    passthrough: bool,
}

/// Per-pool, per-range accumulator. Positions MUST arrive contiguously (they
/// come from `from_state` tree sizes, which are contiguous by construction).
pub(crate) struct ShardAccumulator<H> {
    next_position: u64,
    open: Option<OpenShard<H>>,
}

impl<H: Clone> ShardAccumulator<H> {
    /// `resume_rows`: buffered rows already persisted for the shard containing
    /// `start_position` (restart-mid-shard recovery). `store_has_internals`:
    /// the shard store already holds fragment data for that shard (⇒ it was
    /// built before — stay passthrough; any stale buffer rows are the caller's
    /// to delete).
    pub fn seed(start_position: u64, resume_rows: Vec<AccRow<H>>, store_has_internals: bool) -> Self {
        let index = shard_of(start_position);
        debug_assert!(
            resume_rows.iter().all(|(p, ..)| shard_of(*p) == index),
            "resume rows must belong to the seed shard"
        );
        let passthrough = resume_rows.is_empty() && store_has_internals;
        Self {
            next_position: start_position,
            open: Some(OpenShard { index, rows: resume_rows, passthrough }),
        }
    }

    /// Feed one contiguous slice of the commitment stream plus the owned-note
    /// positions discovered in the same put_blocks call.
    pub fn feed(
        &mut self,
        start_position: u64,
        items: Vec<(H, Retention<BlockHeight>)>,
        note_positions: &[u64],
    ) -> Vec<FeedAction<H>> {
        debug_assert_eq!(
            start_position, self.next_position,
            "commitment stream must be contiguous"
        );
        let mut actions = vec![];
        let mut pos = start_position;
        let mut items = items.into_iter();
        let end = start_position + items.len() as u64;

        while pos < end {
            let shard = shard_of(pos);
            // Close-on-transition: the previous shard saw its final position.
            match &mut self.open {
                Some(open) if open.index != shard => {
                    let closed = self.open.take().map(|o| (o.index, o.rows, o.passthrough));
                    if let Some((index, rows, passthrough)) = closed
                        && !passthrough
                    {
                        actions.push(FeedAction::CloseCleanShard { shard_index: index, rows });
                    }
                    self.open =
                        Some(OpenShard { index: shard, rows: vec![], passthrough: false });
                }
                None => {
                    self.open =
                        Some(OpenShard { index: shard, rows: vec![], passthrough: false });
                }
                _ => {}
            }
            // This shard's span of the feed.
            let span_end = end.min((shard + 1) << SHARD_BITS);
            let span_len = (span_end - pos) as usize;
            let span: Vec<AccRow<H>> = (&mut items)
                .take(span_len)
                .enumerate()
                .map(|(i, (h, r))| (pos + i as u64, h, r))
                .collect();
            let has_note = note_positions.iter().any(|p| *p >= pos && *p < span_end);
            let open = self.open.as_mut().unwrap_or_else(|| unreachable!("opened above"));
            if open.passthrough {
                actions.push(FeedAction::Build(span));
            } else if has_note {
                // Eager flush: buffered prefix + this span build in THIS call —
                // the freshly-found note's witness data exists at today's timing.
                open.rows.extend(span);
                let rows = std::mem::take(&mut open.rows);
                open.passthrough = true;
                actions.push(FeedAction::Build(rows));
            } else {
                open.rows.extend(span.iter().cloned());
                actions.push(FeedAction::Buffer(span));
            }
            pos = span_end;
        }
        self.next_position = end;
        actions
    }

    /// Range end / pass end: the open shard never grafts (rule 1). Returns the
    /// rows to build, if any are pending.
    pub fn finish(&mut self) -> Option<FeedAction<H>> {
        let open = self.open.take()?;
        if !open.passthrough && !open.rows.is_empty() {
            Some(FeedAction::Build(open.rows))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type H = u32; // the accumulator is hash-agnostic; a tiny stand-in keeps tests readable

    const SHARD: u64 = 1 << 16;

    fn items(n: u64) -> Vec<(H, Retention<BlockHeight>)> {
        (0..n).map(|i| (i as H, Retention::Ephemeral)).collect()
    }

    fn positions(action: &FeedAction<H>) -> Vec<u64> {
        match action {
            FeedAction::Build(r) | FeedAction::Buffer(r) => r.iter().map(|x| x.0).collect(),
            FeedAction::CloseCleanShard { rows, .. } => rows.iter().map(|x| x.0).collect(),
        }
    }

    #[test]
    fn rule1_eager_flush_on_first_note_then_passthrough() {
        let mut a = ShardAccumulator::<H>::seed(0, vec![], false);
        // Chunk 1: clean prefix → buffered.
        let acts = a.feed(0, items(100), &[]);
        assert!(matches!(&acts[..], [FeedAction::Buffer(r)] if r.len() == 100));
        // Chunk 2: a note at position 150 → ONE Build with prefix + span (0..200).
        let acts = a.feed(100, items(100), &[150]);
        assert_eq!(acts.len(), 1);
        assert!(matches!(&acts[0], FeedAction::Build(r) if r.len() == 200));
        assert_eq!(positions(&acts[0]).first(), Some(&0));
        assert_eq!(positions(&acts[0]).last(), Some(&199));
        // Chunk 3: same shard → straight Build (passthrough).
        let acts = a.feed(200, items(50), &[]);
        assert!(matches!(&acts[..], [FeedAction::Build(r)] if r.len() == 50));
    }

    #[test]
    fn rule2_clean_close_emits_full_rowset_and_reopens_buffering() {
        let mut a = ShardAccumulator::<H>::seed(0, vec![], false);
        let acts = a.feed(0, items(SHARD), &[]);
        assert!(matches!(&acts[..], [FeedAction::Buffer(_)]));
        // First position of shard 1 closes shard 0 clean.
        let acts = a.feed(SHARD, items(10), &[]);
        assert_eq!(acts.len(), 2);
        match &acts[0] {
            FeedAction::CloseCleanShard { shard_index, rows } => {
                assert_eq!(*shard_index, 0);
                assert_eq!(rows.len(), SHARD as usize, "complete row set for the verdict");
            }
            other => panic!("expected close, got {other:?}"),
        }
        assert!(matches!(&acts[1], FeedAction::Buffer(r) if r.len() == 10));
    }

    #[test]
    fn rule3_noted_shard_closes_silently_no_graft_verdict() {
        let mut a = ShardAccumulator::<H>::seed(0, vec![], false);
        let _ = a.feed(0, items(SHARD), &[5]); // noted → flushed passthrough
        let acts = a.feed(SHARD, items(10), &[]);
        // No CloseCleanShard for shard 0 — it was built already.
        assert!(matches!(&acts[..], [FeedAction::Buffer(r)] if r.len() == 10));
    }

    #[test]
    fn rule4_seed_modes() {
        // Fresh: buffering.
        let mut fresh = ShardAccumulator::<H>::seed(10, vec![], false);
        let acts = fresh.feed(10, items(5), &[]);
        assert!(matches!(&acts[..], [FeedAction::Buffer(_)]));
        // Resume: buffered prefix from the DB continues the same shard.
        let prefix: Vec<AccRow<H>> = (0..10u64).map(|p| (p, p as H, Retention::Ephemeral)).collect();
        let mut resumed = ShardAccumulator::<H>::seed(10, prefix, false);
        let acts = resumed.feed(10, items(SHARD - 10), &[]);
        assert!(matches!(&acts[..], [FeedAction::Buffer(_)]));
        let acts = resumed.feed(SHARD, items(1), &[]);
        match &acts[0] {
            FeedAction::CloseCleanShard { rows, .. } => {
                assert_eq!(rows.len(), SHARD as usize, "prefix + resumed rows = complete shard");
                assert_eq!(rows.first().map(|r| r.0), Some(0));
            }
            other => panic!("expected close, got {other:?}"),
        }
        // Store-has-internals: passthrough from the first feed.
        let mut built = ShardAccumulator::<H>::seed(10, vec![], true);
        let acts = built.feed(10, items(5), &[]);
        assert!(matches!(&acts[..], [FeedAction::Build(_)]));
    }

    #[test]
    fn rule5_finish_builds_never_grafts() {
        let mut a = ShardAccumulator::<H>::seed(0, vec![], false);
        let _ = a.feed(0, items(100), &[]);
        match a.finish() {
            Some(FeedAction::Build(rows)) => assert_eq!(rows.len(), 100),
            other => panic!("expected Build, got {other:?}"),
        }
        // Passthrough shard: nothing pending at finish.
        let mut p = ShardAccumulator::<H>::seed(0, vec![], true);
        let _ = p.feed(0, items(100), &[]);
        assert!(p.finish().is_none());
    }

    #[test]
    fn rule6_buffer_actions_carry_only_new_rows() {
        let mut a = ShardAccumulator::<H>::seed(0, vec![], false);
        let first = a.feed(0, items(100), &[]);
        let second = a.feed(100, items(50), &[]);
        assert_eq!(positions(&first[0]), (0..100).collect::<Vec<_>>());
        assert_eq!(positions(&second[0]), (100..150).collect::<Vec<_>>());
    }

    #[test]
    fn straddle_three_shards_mixed() {
        // One feed spanning: tail of shard 0 (clean), all of shard 1 (noted),
        // head of shard 2 (open).
        let start = SHARD - 10;
        let mut a = ShardAccumulator::<H>::seed(start, vec![], false);
        let len = 10 + SHARD + 5;
        let note_in_shard1 = SHARD + 1234;
        let acts = a.feed(start, items(len), &[note_in_shard1]);
        assert_eq!(acts.len(), 4, "buffer tail0? no — close0 comes on transition: {acts:?}");
        // Span walk: [shard0 tail → Buffer], [transition → CloseCleanShard 0],
        // [shard1 noted → Build], [transition to 2: shard1 was passthrough → no close],
        // [shard2 head → Buffer].
        assert!(matches!(&acts[0], FeedAction::Buffer(r) if r.len() == 10));
        assert!(
            matches!(&acts[1], FeedAction::CloseCleanShard { shard_index: 0, rows } if rows.len() == 10)
        );
        assert!(matches!(&acts[2], FeedAction::Build(r) if r.len() == SHARD as usize));
        assert!(matches!(&acts[3], FeedAction::Buffer(r) if r.len() == 5));
        // Finish builds the open shard-2 head.
        match a.finish() {
            Some(FeedAction::Build(rows)) => assert_eq!(rows.len(), 5),
            other => panic!("expected Build, got {other:?}"),
        }
    }

    #[test]
    #[should_panic(expected = "contiguous")]
    fn contiguity_is_enforced_in_debug() {
        let mut a = ShardAccumulator::<H>::seed(0, vec![], false);
        let _ = a.feed(0, items(10), &[]);
        let _ = a.feed(999, items(1), &[]); // gap → debug_assert fires
    }
}
