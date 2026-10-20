use std::panic::{AssertUnwindSafe, catch_unwind};

use zcash_voting as voting;

/// C function pointer type for proof progress reporting.
pub type VotingProgressCallback =
    unsafe extern "C" fn(progress: f64, context: *mut std::ffi::c_void);

/// Bridges a C function pointer to `zcash_voting`'s progress reporter traits.
///
/// Only `ProgressReporter` is implemented here. `zcash_voting` supplies a
/// blanket `impl<T: ProgressReporter> DelegationProgressReporter for T`, so the
/// entry points that demand the staged reporter are satisfied automatically;
/// implementing it by hand would collide with that impl. The blanket version
/// forwards clamped `ProofProgress` fractions and drops the non-proof stages,
/// which matches this callback's contract of a proof-completion fraction.
pub(super) struct ProgressBridge {
    pub(super) callback: VotingProgressCallback,
    pub(super) context: *mut std::ffi::c_void,
}

// SAFETY: The caller guarantees the context pointer is valid for the duration
// of the proof operation and that the callback is thread-safe.
unsafe impl Send for ProgressBridge {}
unsafe impl Sync for ProgressBridge {}

impl voting::ProgressReporter for ProgressBridge {
    fn on_progress(&self, progress: f64) {
        // Progress reporting is best-effort; do not let callback panics unwind
        // through zcash_voting or across the FFI boundary.
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
            (self.callback)(progress, self.context)
        }));
    }
}
