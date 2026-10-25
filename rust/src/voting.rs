//! C FFI for the voting functionality, backed by upstream `zcash_voting` 1.0.
//!
//! Implementation is split into submodules for navigation. Exported FFI functions
//! keep their stable C symbols with `#[unsafe(no_mangle)]`. Entry points that the
//! crate's 1.0 one-shot commit flow absorbed (`encrypt_shares`, `sign_cast_vote`,
//! `store_commitment_bundle`, `decompose_weight`, `generate_delegation_inputs`)
//! keep their symbols as honest "superseded" error stubs.

pub mod confirmation;
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
pub mod signing;
#[cfg(test)]
pub(crate) mod test_helpers;
pub mod tree;
pub mod util;
pub mod vote;
