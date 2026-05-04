
// =============================================================================
// Helper functions
// =============================================================================

/// Parse a byte slice from raw pointer + length.
///
/// # Safety
///
/// - `ptr` must be non-null and valid for reads for `len` bytes.
/// - The memory referenced by `ptr` must not be mutated for the duration of the call.
pub(super) unsafe fn bytes_from_ptr<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    unsafe { std::slice::from_raw_parts(ptr, len) }
}
