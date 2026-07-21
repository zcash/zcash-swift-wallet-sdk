//! The adapter wiring this SDK's wallet database into the pool-migration engine's traits.
//!
//! [`zcash_pool_migration_backend`]'s engine works over four traits — `MigrationBackend` (notes and
//! chain tip), `MigrationCrypto` (viewing key, note plaintexts, signing), and `PoolMigrationRead` /
//! `PoolMigrationWrite` (the store). The crate ships its own `wallet::WalletMigration` adapter, but
//! that adapter requires a `UnifiedSpendingKey` unconditionally (it derives the Orchard FVK from
//! it), which cannot serve an imported hardware-wallet account whose spending key never exists on
//! this device. This adapter instead derives the FVK from the account's STORED unified full viewing
//! key, takes the spending key as an `Option` (present only on the in-process signing paths), and
//! scopes the store to the account via `PoolMigrations::for_account` — so one wallet database
//! hosting several accounts (a seed-derived software account next to a UFVK-imported Keystone
//! account) migrates them independently.
//!
//! Engine-driven proving (`MigrationCrypto::prove_transfer`) is deliberately NOT used by this FFI:
//! resolving witnesses needs mutable access to the wallet's note commitment tree, which the shared
//! borrow this adapter holds cannot provide. Proving lives in [`crate::migration_finalize`]
//! instead, which is also where the migration's anchor policy (and its current ZIP 318 deviation)
//! is isolated.

use anyhow::anyhow;
use orchard::keys::{FullViewingKey, SpendAuthorizingKey};
use orchard::note::Note as OrchardNote;
use incrementalmerkletree::Position;
use rand::rngs::OsRng;
use zcash_client_backend::data_api::wallet::TargetHeight;
use zcash_client_backend::data_api::{Account, InputSource, WalletRead};
use zcash_client_sqlite::AccountUuid;
use zcash_client_sqlite::util::SystemClock;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_pool_migration_backend::build::sign_pczt;
use zcash_pool_migration_backend::engine::{
    MigrationBackend, MigrationCrypto, MigrationState, MigrationTxId, MigrationTxState,
    PoolMigrationRead, PoolMigrationWrite,
};
use zcash_pool_migration_sqlite::orchard_ironwood::PoolMigrations;
use zcash_protocol::ShieldedPool;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;

use crate::NetworkParams;

/// The concrete wallet type every migration entry point operates over.
pub(crate) type MigrationWallet =
    zcash_client_sqlite::WalletDb<rusqlite::Connection, NetworkParams, SystemClock, OsRng>;

/// A spendable Orchard note as the adapter tracks it: the note, its note-commitment-tree position,
/// and its value in zatoshi. The vector's order (sorted by tree position) is the index space the
/// engine's `PrepInput::Wallet { index }` refers into, so it must be stable across calls.
pub(crate) type SpendableNote = (OrchardNote, Position, u64);

/// The migration backend for one account of this SDK's wallet database.
pub(crate) struct Backend<'a> {
    wallet: &'a MigrationWallet,
    account: AccountUuid,
    usk: Option<UnifiedSpendingKey>,
    store: PoolMigrations<&'a mut rusqlite::Connection>,
}

impl<'a> Backend<'a> {
    /// Wrap the wallet, an account, an optional spending key (present only for in-process signing
    /// paths — the external-signer and read/plan paths pass `None`), and the store connection.
    pub(crate) fn new(
        wallet: &'a MigrationWallet,
        account: AccountUuid,
        usk: Option<UnifiedSpendingKey>,
        store_conn: &'a mut rusqlite::Connection,
    ) -> Self {
        Self {
            wallet,
            account,
            usk,
            store: PoolMigrations::for_account(store_conn, account.expose_uuid()),
        }
    }

    /// The target height for note selection (the chain tip plus one).
    fn selection_target(&self) -> anyhow::Result<TargetHeight> {
        let tip = self
            .wallet
            .chain_height()
            .map_err(|e| anyhow!("chain height lookup failed: {e}"))?
            .ok_or_else(|| anyhow!("the wallet has no chain tip yet; sync first"))?;
        Ok(TargetHeight::from(u32::from(tip) + 1))
    }

    /// The account's spendable Orchard notes as `(note, tree position, value)`, sorted by tree
    /// position so the index is stable across calls (the engine maps a value index from
    /// `spendable_orchard_note_values` back to a note by the same order).
    pub(crate) fn spendable_orchard_notes(&self) -> anyhow::Result<Vec<SpendableNote>> {
        let target = self.selection_target()?;
        let received = self
            .wallet
            .select_unspent_notes(self.account, &[ShieldedPool::Orchard], target, &[])
            .map_err(|e| anyhow!("spendable-note selection failed: {e}"))?;
        let mut notes: Vec<SpendableNote> = received
            .orchard()
            .iter()
            .map(|rn| {
                let note = *rn.note();
                let value = note.value().inner();
                (note, rn.note_commitment_tree_position(), value)
            })
            .collect();
        notes.sort_by_key(|(_, pos, _)| *pos);
        Ok(notes)
    }

    /// The account's Orchard full viewing key, from its STORED unified full viewing key (not the
    /// spending key), so read/plan/build paths work for accounts whose spending key never exists
    /// on this device (an imported hardware-wallet account).
    pub(crate) fn stored_orchard_fvk(&self) -> anyhow::Result<FullViewingKey> {
        let account = self
            .wallet
            .get_account(self.account)
            .map_err(|e| anyhow!("account lookup failed: {e}"))?
            .ok_or_else(|| anyhow!("unknown account"))?;
        let ufvk = account
            .ufvk()
            .ok_or_else(|| anyhow!("the account has no unified full viewing key"))?;
        ufvk.orchard()
            .cloned()
            .ok_or_else(|| anyhow!("the account's viewing key has no Orchard component"))
    }
}

impl MigrationBackend for Backend<'_> {
    type Error = anyhow::Error;

    fn spendable_orchard_note_values(&self) -> Result<Vec<Zatoshis>, Self::Error> {
        self.spendable_orchard_notes()?
            .into_iter()
            .enumerate()
            .map(|(i, (_, _, value))| {
                Zatoshis::from_u64(value)
                    .map_err(|_| anyhow!("spendable note {i} has an out-of-range value"))
            })
            .collect()
    }

    fn chain_tip_height(&self) -> Result<BlockHeight, Self::Error> {
        self.wallet
            .chain_height()
            .map_err(|e| anyhow!("chain height lookup failed: {e}"))?
            .ok_or_else(|| anyhow!("the wallet has no chain tip yet; sync first"))
    }
}

impl MigrationCrypto for Backend<'_> {
    type Error = anyhow::Error;

    fn orchard_fvk(&self) -> Result<FullViewingKey, Self::Error> {
        self.stored_orchard_fvk()
    }

    fn resolve_wallet_note(&self, index: usize) -> Result<OrchardNote, Self::Error> {
        let notes = self.spendable_orchard_notes()?;
        let &(note, _, _) = notes
            .get(index)
            .ok_or_else(|| anyhow!("no spendable note at index {index}"))?;
        Ok(note)
    }

    fn sign(&self, pczt: pczt::Pczt) -> Result<pczt::Pczt, Self::Error> {
        let usk = self
            .usk
            .as_ref()
            .ok_or_else(|| anyhow!("signing requires the account's spending key"))?;
        let ask = SpendAuthorizingKey::from(usk.orchard());
        sign_pczt(pczt, &ask).map_err(|e| anyhow!("signing the migration failed: {e}"))
    }

    fn prove_transfer(
        &self,
        _pczt: pczt::Pczt,
        _anchor_boundary: BlockHeight,
    ) -> Result<pczt::Pczt, Self::Error> {
        // Never called: this FFI does not drive the engine's `prove_transfer` flow, because
        // resolving witnesses needs `&mut` access to the wallet's note commitment tree, which this
        // adapter's shared wallet borrow cannot provide. Proving lives in
        // `crate::migration_finalize` (see its module doc for the anchor policy and the current
        // ZIP 318 deviation).
        Err(anyhow!(
            "engine-driven proving is not used by this FFI; proving lives in migration_finalize"
        ))
    }
}

impl PoolMigrationRead for Backend<'_> {
    type Error = anyhow::Error;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        self.store
            .get_migration()
            .map_err(|e| anyhow!("migration store read failed: {e}"))
    }
}

impl PoolMigrationWrite for Backend<'_> {
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.store
            .replace_migration(state)
            .map_err(|e| anyhow!("migration store write failed: {e}"))
    }

    fn update_transaction(
        &mut self,
        id: MigrationTxId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        self.store
            .update_transaction(id, state)
            .map_err(|e| anyhow!("migration store update failed: {e}"))
    }
}
