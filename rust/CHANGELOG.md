# Unreleased

Unified spending keys are now used in all places where spending authority
is required, both for performing spends of shielded funds and for shielding
transparent funds. Unified spending keys are represented as opaque arrays
of bytes, and FFI methods are provided to permit derivation of viewing keys
from the binary unified spending key representation.

IMPORTANT NOTE: the binary representation of a unified spending key may be
cached, but may become invalid and require re-derivation from seed to use as
input to any of the relevant APIs in the future, in the case that the
representation of the spending key changes or new types of spending authority
are recognized.  Spending keys give irrevocable spend authority over
a specific account.  Clients that choose to store the binary representation
of unified spending keys locally on device, should handle them with the 
same level of care and secure storage policies as the wallet seed itself. 

## Added
- `zcashlc_create_account` provides new account creation functionality.
  This is now the preferred API for the creation of new spend authorities
  within the wallet; `zcashlc_init_accounts_table_with_keys` remains available
  but should only be used if it is necessary to add multiple accounts at once,
  such as when restoring a wallet from seed where multiple accounts had been
  previously derived.

Key derivation API:
- `zcashlc_derive_spending_key`
- `zcashlc_spending_key_to_full_viewing_key`

Address retrieval, derivation, and verification API:
- `zcashlc_get_current_address`
- `zcashlc_get_next_available_address`
- `zcashlc_get_sapling_receiver_for_unified_address`
- `zcashlc_get_transparent_receiver_for_unified_address`
- `zcashlc_is_valid_unified_address`
- `zcashlc_is_valid_unified_full_viewing_key`
- `zcashlc_list_transparent_receivers`
- `zcashlc_get_typecodes_for_unified_address_receivers`
- `zcashlc_free_typecodes`
- `zcashlc_get_address_metadata`
Balance API:
- `zcashlc_get_verified_transparent_balance_for_account`
- `zcashlc_get_total_transparent_balance_for_account`

New memo access API:
- `zcashlc_get_received_memo`
- `zcashlc_get_sent_memo`

## Changed
- `zcashlc_create_to_address` now has been changed as follows:
  - it no longer takes the string encoding of a Sapling extended spending key
    as spend authority; instead, it takes the binary encoded form of a unified
    spending key as returned by `zcashlc_create_account` or 
    `zcashlc_derive_spending_key`. See the note above.
  - it now takes the minimum number of confirmations used to filter notes to
    spend as an argument.
  - the memo argument is now passed as a potentially-null pointer to an
    `[u8; 512]` instead of a C string.
- `zcashlc_shield_funds` has been changed as follows:
  - it no longer takes the transparent spending key for a single P2PKH address
    as spend authority; instead, it takes the binary encoded form of a unified
    spending key as returned by `zcashlc_create_account`
    or `zcashlc_derive_spending_key`. See the note above.
  - the memo argument is now passed as a potentially-null pointer to an
    `[u8; 512]` instead of a C string.
  - it no longer takes a destination address; instead, the internal shielding
    address is automatically derived from the account ID.
- Various changes have been made to correctly implement ZIP 316:
  - `FFIUnifiedViewingKey` now stores an account ID and the encoding of a
    ZIP 316 Unified Full Viewing Key.
  - `zcashlc_init_accounts_table_with_keys` now takes a slice of ZIP 316 UFVKs.
- `zcashlc_put_utxo` no longer has an `address_str` argument (the address is
  instead inferred from the script).
- `zcashlc_get_verified_balance` now takes the minimum number of confirmations
  used to filter received notes as an argument.
- `zcashlc_get_verified_transparent_balance` now takes the minimum number of
  confirmations used to filter received notes as an argument.
- `zcashlc_get_total_transparent_balance` now returns a balance that includes
  all UTXOs including those only in the mempool (i.e. those with 0
  confirmations).

## Removed

The following spending key derivation APIs have been removed and replaced by
`zcashlc_derive_spending_key`:
- `zcashlc_derive_extended_spending_key`
- `zcashlc_derive_transparent_private_key_from_seed`
- `zcashlc_derive_transparent_account_private_key_from_seed`

The following viewing key APIs have been removed and replaced by
`zcashlc_spending_key_to_full_viewing_key`:
- `zcashlc_derive_extended_full_viewing_key`
- `zcashlc_derive_shielded_address_from_viewing_key`
- `zcashlc_derive_unified_viewing_keys_from_seed`

The following address derivation APIs have been removed in favor of
`zcashlc_get_current_address` and `zcashlc_get_next_available_address`:
- `zcashlc_get_address`
- `zcashlc_derive_shielded_address_from_seed`
- `zcashlc_derive_transparent_address_from_secret_key`
- `zcashlc_derive_transparent_address_from_seed`
- `zcashlc_derive_transparent_address_from_public_key`

- `zcashlc_init_accounts_table` has been removed in favor of
  `zcashlc_create_account`

# 0.0.3
- [#13] Migrate to `zcash/librustzcash` revision with NU5 awareness (#20)
  This enables mobile wallets to send transactions after NU5 activation.
