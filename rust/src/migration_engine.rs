//! The adapter wiring this SDK's wallet database into the pool-migration engine's traits.
//!
//! [`zcash_pool_migration`]'s engine works over four traits — `MigrationBackend` (notes and
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
//! Proving (`engine::MigrationProver`) is deliberately NOT implemented on this adapter: resolving
//! witnesses needs mutable access to the wallet's note commitment tree, which the shared borrow
//! this adapter holds cannot provide. The proving entry points instead construct the upstream
//! `wallet::WalletMigrationProver` over a separate mutable wallet borrow, dispatched per
//! transaction kind (boundary anchor for transfers, preparation anchor for preparations) in
//! [`crate::migration_finalize`].

use anyhow::anyhow;
use incrementalmerkletree::Position;
use orchard::keys::{FullViewingKey, SpendAuthorizingKey};
use orchard::note::Note as OrchardNote;
use rand::rngs::OsRng;
use zcash_client_backend::data_api::wallet::{
    TargetHeight,
    input_selection::{LockFilter, LockedInputPolicy},
};
use zcash_client_backend::data_api::{Account, InputSource, WalletRead};
use zcash_client_sqlite::AccountUuid;
use zcash_client_sqlite::pool_migration::orchard_ironwood::PoolMigrations;
use zcash_client_sqlite::util::SystemClock;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_pool_migration::build::{AccountDerivation, sign_pczt};
use zcash_pool_migration::engine::{
    MigrationBackend, MigrationCrypto, MigrationState, MigrationTransaction, MigrationTransferId,
    MigrationTxState, PoolMigrationRead, PoolMigrationWrite, ProvedTransaction,
};
use zcash_pool_migration::scheduling::SchedulingParams;
use zcash_protocol::ShieldedPool;
use zcash_protocol::TxId;
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
    store: PoolMigrations<&'a mut rusqlite::Connection, NetworkParams, SystemClock>,
}

impl<'a> Backend<'a> {
    /// Wrap the wallet, an account, an optional spending key (present only for in-process signing
    /// paths — the external-signer and read/plan paths pass `None`), and the store connection.
    pub(crate) fn new(
        wallet: &'a MigrationWallet,
        account: AccountUuid,
        usk: Option<UnifiedSpendingKey>,
        store_conn: &'a mut rusqlite::Connection,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            wallet,
            account,
            usk,
            // `params` and `clock` serve the store's `store_proved_transaction` (it finalizes the
            // proven transaction into the wallet's own tables, which needs the network's branch
            // ids and a creation timestamp); both come from the same sources the wallet itself
            // was built with.
            store: PoolMigrations::for_account(
                wallet.params().clone(),
                SystemClock,
                store_conn,
                account,
            )
            .map_err(|e| anyhow!("opening the account-scoped migration store failed: {e}"))?,
        })
    }

    /// The account's most recent stored migration WHATEVER its status, where
    /// [`PoolMigrationRead::get_migration`] reports only a PENDING one.
    ///
    /// The two answers coincide until a run reaches a terminal status; from that moment
    /// `get_migration` returns `None` and the record is readable only here. Every SDK entry point
    /// that must still SEE a finished or cancelled run — reporting it complete, or listing the
    /// transactions it mined — reads through this, and keeps its own `is_terminal()` branch to
    /// decide what a terminal run means for that particular answer. Entry points that act ON a run
    /// (committing, signing, proving, broadcasting, replanning) read `get_migration` instead, so
    /// the store's own pending-only filter is what keeps them off a record nothing will drive.
    ///
    /// Inherent rather than part of [`PoolMigrationRead`] because the engine never reads history:
    /// upstream keeps it off the trait for the same reason.
    pub(crate) fn latest_migration(&self) -> anyhow::Result<Option<MigrationState>> {
        self.store
            .latest_migration()
            .map_err(|e| anyhow!("migration store history read failed: {e}"))
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
            .select_unspent_notes(
                self.account,
                &[ShieldedPool::Orchard],
                target,
                &[],
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )
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

    /// The anchor bucket grid is the wallet's own anchor retention interval (selected per network
    /// in [`crate::wallet_db`]), so a transfer can only anchor to a boundary whose checkpoint this
    /// wallet retains; the delay distributions scale each ZIP 318 delay mean and cap by the ratio
    /// of the interval to the 144-block ZIP 318 one, which reproduces the specified schedule
    /// exactly on the standard 144-block grid and compresses it by the same factor on a shortened
    /// one.
    fn scheduling_params(&self) -> SchedulingParams {
        SchedulingParams::new_with_default_distributions(
            self.wallet.anchor_retention_interval().into(),
        )
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

    /// The account's ZIP 32 derivation as the wallet records it, or `None` for an account held
    /// only as a viewing key. The builders stamp this onto every spend still awaiting a
    /// signature, which is how an external signer recognizes those spends as this account's;
    /// returning it unconditionally (rather than only when signing is delegated) keeps the
    /// in-process and hardware-wallet paths producing identical PCZTs.
    fn account_derivation(&self) -> Result<Option<AccountDerivation>, Self::Error> {
        Ok(self
            .wallet
            .get_account(self.account)
            .map_err(|e| anyhow!("account lookup failed: {e}"))?
            .and_then(|account| {
                account
                    .source()
                    .key_derivation()
                    .map(AccountDerivation::from)
            }))
    }

    fn sign(&self, pczt: pczt::Pczt) -> Result<pczt::Pczt, Self::Error> {
        let usk = self
            .usk
            .as_ref()
            .ok_or_else(|| anyhow!("signing requires the account's spending key"))?;
        let ask = SpendAuthorizingKey::from(usk.orchard());
        sign_pczt(pczt, &ask).map_err(|e| anyhow!("signing the migration failed: {e}"))
    }
}

impl PoolMigrationRead for Backend<'_> {
    type Error = anyhow::Error;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        self.store
            .get_migration()
            .map_err(|e| anyhow!("migration store read failed: {e}"))
    }

    fn check_step_satisfiability(
        &self,
        tx: &MigrationTransaction,
        settle: zcash_pool_migration::satisfiability::ReorgSettleDepth,
    ) -> Result<zcash_pool_migration::satisfiability::StepSatisfiability, Self::Error> {
        self.store
            .check_step_satisfiability(tx, settle)
            .map_err(|e| anyhow!("migration satisfiability check failed: {e}"))
    }

    /// Delegated to the store, which reads the wallet's own `transactions` table bounded by the
    /// FULLY-SCANNED height — a stricter bound than `WalletRead::get_tx_height`'s chain tip, and
    /// the reason the SDK no longer runs its own mined-height lookup: a promotion may not rest on
    /// a block outside the region a reorg truncation would roll back.
    fn mined_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        self.store
            .mined_height(txid)
            .map_err(|e| anyhow!("mined-height lookup failed: {e}"))
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
        id: MigrationTransferId,
        state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        self.store
            .update_transaction(id, state)
            .map_err(|e| anyhow!("migration store update failed: {e}"))
    }

    fn store_proved_transaction(
        &mut self,
        state: &mut MigrationState,
        proven: ProvedTransaction,
    ) -> Result<(), Self::Error> {
        self.store
            .store_proved_transaction(state, proven)
            .map_err(|e| anyhow!("migration store proved-transaction write failed: {e}"))
    }
}
