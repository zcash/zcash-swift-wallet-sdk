#![allow(clippy::missing_safety_doc, unused_imports)]

//! C FFI for the voting functionality.
//!
//! Follows the same patterns as `lib.rs` and `ffi.rs`:
//! - Functions: `#[unsafe(no_mangle)] pub unsafe extern "C" fn zcashlc_voting_*()`
//! - Error handling: `catch_panic()` + `unwrap_exc_or_null()` / `unwrap_exc_or()`
//! - Opaque pointers: `Box::into_raw(Box::new(obj))` to create, `Box::from_raw(ptr)` to free
//! - Complex types: JSON serialization via serde across the FFI boundary
//! - Simple types: `#[repr(C)]` structs
//!
//! Implementation is split into submodules for navigation. Each FFI file is declared with
//! `pub mod name` **and** `pub use name::*`: the module keeps a real namespace (`crate::voting::name::…`),
//! while the glob re-exports the same public items at `crate::voting::…`. That exposes the APIs
//! at the parent level, so cbindgen and any `use crate::voting::…` imports can conveniently refer
//! to the same items without having to know the module hierarchy.
//!
//! Sibling files still refer to each other with explicit `super::name::…` imports.

// Shared helpers used only between voting submodules (`super::helpers`, etc.).
mod helpers;
mod json;
mod progress;
mod util;

pub mod db;
pub use db::*;

pub mod delegation;
pub use delegation::*;

pub mod ffi_types;
pub use ffi_types::*;

pub mod notes;
pub use notes::*;

pub mod recovery;
pub use recovery::*;

pub mod rounds;
pub use rounds::*;

pub mod share_tracking;
pub use share_tracking::*;

pub mod tree;
pub use tree::*;

pub mod vote;
pub use vote::*;
