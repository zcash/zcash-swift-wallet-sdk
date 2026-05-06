use serde::Serialize;

/// Parse a UTF-8 string from a raw pointer and length.
///
/// # Safety
///
/// - `ptr` must be non-null and valid for reads for `len` bytes.
/// - The memory referenced by `ptr` must not be mutated for the duration of the call.
pub(super) unsafe fn str_from_ptr(ptr: *const u8, len: usize) -> anyhow::Result<String> {
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    Ok(std::str::from_utf8(bytes)?.to_string())
}

/// Return JSON-serialized bytes as `*mut ffi::BoxedSlice`.
pub(super) fn json_to_boxed_slice<T: Serialize>(
    value: &T,
) -> anyhow::Result<*mut crate::ffi::BoxedSlice> {
    let json = serde_json::to_vec(value)?;
    Ok(crate::ffi::BoxedSlice::some(json))
}
