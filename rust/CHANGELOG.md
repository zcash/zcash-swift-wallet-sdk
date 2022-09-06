# Unreleased
## Added
- `zcashlc_is_valid_unified_address`
- `zcashlc_is_valid_unified_full_viewing_key`
- `zcashlc_derive_transparent_account_private_key_from_seed`
- `zcashlc_derive_transparent_address_from_account_private_key`
- `zcashlc_derive_unified_address_from_seed`
- `zcashlc_derive_unified_address_from_viewing_key`
- `zcashlc_derive_unified_full_viewing_keys_from_seed`
- `zcashlc_get_received_memo`
- `zcashlc_get_sent_memo`

## Changed
- Various changes have been made to correctly implement ZIP 316:
  - `FFIUnifiedViewingKey` now stores an account ID and the encoding of a
    ZIP 316 Unified Full Viewing Key.
  - `zcashlc_init_accounts_table_with_keys` now takes a slice of ZIP 316 UFVKs.
- `zcashlc_put_utxo` no longer has an `address_str` argument (the address is
  instead inferred from the script).
- `zcashlc_shield_funds` now takes the transparent account private key as an
  argument instead of the transparent spending key for a single P2PKH address.
- `zcashlc_get_verified_balance` now takes the minimum number of confirmations
  used to filter received notes as an argument.
- `zcashlc_get_verified_transparent_balance` now takes the minimum number of
  confirmations used to filter received notes as an argument.
- `zcashlc_get_total_transparent_balance` now returns a balance that includes
  all UTXOs up to those in the latest block (i.e. those with 0 confirmations.)
- `zcashlc_create_to_address` now takes the minimum number of confirmations
  used to filter notes to spend as an argument. Also, the memo argument is
  now passed as a potentially-null pointer to an `[u8; 512]` instead of a
  C string.

## Removed
- `zcashlc_derive_shielded_address_from_seed`
- `zcashlc_derive_shielded_address_from_viewing_key`
- `zcashlc_derive_transparent_address_from_secret_key`
- `zcashlc_derive_transparent_private_key_from_seed`
- `zcashlc_derive_unified_viewing_keys_from_seed`

# 0.0.3
- [#13] Migrate to `zcash/librustzcash` revision with NU5 awareness (#20)
  This enables mobile wallets to send transactions after NU5 activation.
