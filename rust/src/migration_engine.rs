//! What remains SDK-side of wiring this wallet database into the pool-migration engine.
//!
//! [`zcash_pool_migration`]'s engine works over four traits — `MigrationBackend` (notes and chain
//! tip), `MigrationCrypto` (viewing key, note plaintexts), and `PoolMigrationRead` /
//! `PoolMigrationWrite` (the store). Both halves are upstream's: the crate's own
//! [`WalletMigration`] adapter serves the first two over any `zcash_client_backend` wallet, and
//! `zcash_client_sqlite`'s account-scoped `PoolMigrations` is the store it wraps. This SDK no
//! longer forks either. What is left here is the three joints that are genuinely this wallet's:
//!
//! - [`account_store`] opens the account-scoped store. `PoolMigrations::for_account` needs the
//!   network parameters and clock the wallet handle itself was built with (its
//!   `store_proved_transaction` finalizes into the wallet's own tables, which needs branch ids and
//!   a creation timestamp), and it scopes the migration to ONE account — so a wallet database
//!   hosting a seed-derived account next to a UFVK-imported Keystone account migrates them
//!   independently. Every operation that is purely a store operation takes this directly.
//! - [`stored_ufvk`] is the one thing upstream deliberately leaves to the caller: [`WalletMigration`]
//!   takes the account's unified full viewing key as a CONSTRUCTOR PARAMETER rather than reading
//!   the account record, because a wallet may hold several keys that view one account and only the
//!   caller knows which the migration's notes belong to. This SDK's answer is always the key the
//!   account record stores, which is also what lets an imported hardware-wallet account — whose
//!   spending key never exists on this device — plan, build and prove here.
//! - [`account_migration`] is the two together: the adapter every engine call that needs
//!   `MigrationBackend` / `MigrationCrypto` (planning, estimating, committing, rebuilding) is
//!   handed.
//!
//! There is no spending key in this module, and no way to give the adapter one — [`WalletMigration`]
//! holds viewing authority and offers no constructor that takes more. The engine's two signing
//! entry points take an `orchard::keys::SpendingKey` per call — deriving its full viewing key and
//! refusing eagerly if it does not match the account's, before building anything — so the FFI
//! functions that sign pass the spending key they just decoded straight through and drop it with
//! the call.
//!
//! Proving (`engine::MigrationProver`) is upstream's `wallet::WalletMigrationProver` over a
//! separate MUTABLE wallet borrow: resolving witnesses needs the note commitment tree, which the
//! shared borrow the adapter holds cannot provide. It is dispatched per transaction kind (boundary
//! anchor for transfers, preparation anchor for preparations) in [`crate::migration_finalize`],
//! and takes the account's Orchard viewing key from [`stored_orchard_fvk`].

use anyhow::anyhow;
use orchard::keys::FullViewingKey;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use zcash_client_backend::data_api::{Account, InputSource, WalletRead};
use zcash_client_sqlite::AccountUuid;
use zcash_client_sqlite::pool_migration::orchard_ironwood::{
    Error as PoolMigrationStoreError, PoolMigrations,
};
use zcash_client_sqlite::util::SystemClock;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_pool_migration::wallet::WalletMigration;

use crate::NetworkParams;

/// The concrete wallet type every migration entry point operates over.
pub(crate) type MigrationWallet = zcash_client_sqlite::WalletDb<
    rusqlite::Connection,
    NetworkParams,
    SystemClock,
    UnwrapErr<SysRng>,
>;

/// The account-scoped pool-migration store, over the second connection into the wallet database
/// file that every migration call opens ([`crate::migration`]'s `CallCtx::store_conn`).
pub(crate) type MigrationStore<'a> =
    PoolMigrations<&'a mut rusqlite::Connection, NetworkParams, SystemClock>;

/// The upstream migration adapter over this SDK's wallet handle and store.
pub(crate) type AccountMigration<'a> = WalletMigration<'a, MigrationWallet, MigrationStore<'a>>;

/// The adapter's error type: upstream's three-way split over the wallet's read and note-source
/// errors and the store's own. Every engine call made through an [`AccountMigration`] reports
/// through it (as `CommitError<AdapterError>`, `RebuildError<AdapterError>`, and so on).
pub(crate) type AdapterError = zcash_pool_migration::wallet::Error<
    <MigrationWallet as WalletRead>::Error,
    <MigrationWallet as InputSource>::Error,
    PoolMigrationStoreError,
>;

/// Open the account-scoped migration store over `store_conn`.
///
/// This is the whole seam for every operation that only ever touches the store: the
/// history-inclusive `latest_migration` (upstream's `PoolMigrationRead::get_migration` is
/// PENDING-ONLY, so the reads that must keep serving a completed, failed or cancelled run read
/// through the store's own accessor), the atomic broadcast seam, cancellation, and the drive's
/// `advance_migration` — none of which needs a viewing key, and so none of which asks for one.
pub(crate) fn account_store<'a>(
    wallet: &MigrationWallet,
    account: AccountUuid,
    store_conn: &'a mut rusqlite::Connection,
) -> anyhow::Result<MigrationStore<'a>> {
    PoolMigrations::for_account(wallet.params().clone(), SystemClock, store_conn, account)
        .map_err(|e| anyhow!("opening the account-scoped migration store failed: {e}"))
}

/// The account's STORED unified full viewing key — the key this SDK builds every migration
/// against.
///
/// The one thing upstream's adapter asks its caller for. A hard error when the account record
/// holds no key: nothing downstream of it can proceed without one, and the alternative (deferring
/// to whichever engine call first needs the Orchard component) would report the same condition
/// later and less clearly.
pub(crate) fn stored_ufvk(
    wallet: &MigrationWallet,
    account: AccountUuid,
) -> anyhow::Result<UnifiedFullViewingKey> {
    wallet
        .get_account(account)
        .map_err(|e| anyhow!("account lookup failed: {e}"))?
        .ok_or_else(|| anyhow!("unknown account"))?
        .ufvk()
        .cloned()
        .ok_or_else(|| anyhow!("the account has no unified full viewing key"))
}

/// The Orchard component of [`stored_ufvk`], for the one consumer that needs it outside the
/// adapter: `wallet::WalletMigrationProver`, which recomputes each spend's nullifier under it to
/// locate the note in the wallet's commitment tree.
pub(crate) fn stored_orchard_fvk(
    wallet: &MigrationWallet,
    account: AccountUuid,
) -> anyhow::Result<FullViewingKey> {
    stored_ufvk(wallet, account)?
        .orchard()
        .cloned()
        .ok_or_else(|| anyhow!("the account's viewing key has no Orchard component"))
}

/// The migration adapter for one account: upstream's [`WalletMigration`] over this wallet handle,
/// the account's stored viewing key, and its scoped store.
///
/// Construct one per FFI call and drop it with the call — the adapter snapshots the account's
/// spendable notes on first read (the engine addresses a note by its index into that sequence, so
/// every read through one adapter must see the same set), and wallet changes are observed by
/// constructing a fresh one.
pub(crate) fn account_migration<'a>(
    wallet: &'a MigrationWallet,
    account: AccountUuid,
    store_conn: &'a mut rusqlite::Connection,
) -> anyhow::Result<AccountMigration<'a>> {
    let ufvk = stored_ufvk(wallet, account)?;
    let store = account_store(wallet, account, store_conn)?;
    Ok(WalletMigration::new(wallet, account, ufvk, store))
}
