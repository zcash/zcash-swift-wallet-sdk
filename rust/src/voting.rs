//! C FFI for the voting functionality.
//!
//! Implementation is split into submodules for navigation. Exported FFI functions
//! keep their stable C symbols with `#[unsafe(no_mangle)]`.

// Shared helpers used only between voting submodules (`super::helpers`, etc.).
mod helpers;
pub mod share_tracking;
