//! C FFI for the voting functionality.
//!
//! Implementation is split into submodules for navigation. Exported FFI functions
//! keep their stable C symbols with `#[unsafe(no_mangle)]`.

mod constants;
pub mod db;
pub mod delegation;
pub mod ffi_types;
pub mod helpers;
pub mod json;
pub mod notes;
pub mod progress;
pub mod recovery;
pub mod rounds;
pub mod share_tracking;
#[cfg(test)]
pub(crate) mod test_helpers;
pub mod tree;
pub mod util;
pub mod vote;
