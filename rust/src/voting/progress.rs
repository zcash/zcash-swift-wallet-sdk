use std::panic::{AssertUnwindSafe, catch_unwind};

use zcash_voting as voting;

/// C function pointer type for proof progress reporting.
pub type VotingProgressCallback =
    unsafe extern "C" fn(progress: f64, context: *mut std::ffi::c_void);

/// Bridges a C function pointer to the `ProofProgressReporter` trait.
pub(super) struct ProgressBridge {
    pub(super) callback: VotingProgressCallback,
    pub(super) context: *mut std::ffi::c_void,
}

// SAFETY: The caller guarantees the context pointer is valid for the duration
// of the proof operation and that the callback is thread-safe.
unsafe impl Send for ProgressBridge {}
unsafe impl Sync for ProgressBridge {}

impl voting::ProofProgressReporter for ProgressBridge {
    fn on_progress(&self, progress: f64) {
        // Progress reporting is best-effort; do not let callback panics unwind
        // through zcash_voting or across the FFI boundary.
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
            (self.callback)(progress, self.context)
        }));
    }
}
