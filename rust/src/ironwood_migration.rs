//! Orchard -> Ironwood migration: denomination planning.
//!
//! Splits a wallet's spendable Orchard balance into round-ZEC-denominated
//! outputs (1, 10, 100... ZEC) plus an optional sub-ZEC residual, so that a
//! later Orchard -> Ironwood transfer moves one round-numbered note at a
//! time instead of the whole balance in one visible pool-crossing transfer.
//!
//! This module intentionally contains only the planning arithmetic. Building,
//! signing, and broadcasting the resulting transactions happens per-step on
//! each guided app-open (no pre-signed batch, no background scheduling) -
//! see `.claude/context/ironwood-migration-port-plan.md` at the zodl repo
//! root for the full design rationale. Kept in lockstep with the equivalent
//! module in `zcash-android-wallet-sdk/backend-lib`.

use ffi_helpers::panic::catch_panic;

use crate::{ptr_from_vec, unwrap_exc_or_null};

pub(crate) const ZATOSHIS_PER_ZEC: u64 = 100_000_000;

/// Upper bound on how many denomination outputs a single split plan may
/// produce, to keep the resulting self-send transaction's output count
/// (and fee) bounded.
pub(crate) const MAX_DENOMINATION_OUTPUTS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DenominationPlan {
    /// Round-ZEC-denominated output values, descending order of denomination.
    pub migration_outputs: Vec<u64>,
    /// Sub-ZEC residual kept as Orchard change rather than migrated, when it's
    /// too small to be worth a dedicated migration output but still above the
    /// minimum output threshold.
    pub orchard_change: Option<u64>,
    pub prep_fee_zatoshi: u64,
    pub migration_fee_zatoshi: u64,
    pub total_input_zatoshi: u64,
    pub total_migratable_zatoshi: u64,
}

/// Plans how to split `total_input_zatoshi` of spendable Orchard balance into
/// round-ZEC denomination outputs.
///
/// `prep_fee_zatoshi` is the fee for the denomination-split transaction
/// itself; `migration_fee_zatoshi` and `minimum_output_zatoshi` determine
/// whether a sub-ZEC residual becomes its own output, becomes Orchard change,
/// or is folded into the prep fee as dust.
pub(crate) fn plan_denominations(
    total_input_zatoshi: u64,
    prep_fee_zatoshi: u64,
    migration_fee_zatoshi: u64,
    minimum_output_zatoshi: u64,
) -> Result<DenominationPlan, String> {
    if total_input_zatoshi <= prep_fee_zatoshi {
        return Ok(DenominationPlan {
            migration_outputs: Vec::new(),
            orchard_change: None,
            prep_fee_zatoshi: total_input_zatoshi,
            migration_fee_zatoshi,
            total_input_zatoshi,
            total_migratable_zatoshi: 0,
        });
    }

    let available = total_input_zatoshi
        .checked_sub(prep_fee_zatoshi)
        .ok_or("Denomination prep fee underflow")?;
    let whole_zec = available / ZATOSHIS_PER_ZEC;
    let mut remainder = available % ZATOSHIS_PER_ZEC;
    let mut outputs = Vec::new();

    let mut denom = 1u64;
    while denom <= whole_zec / 10 {
        denom = denom.checked_mul(10).ok_or("Denomination overflow")?;
    }

    let mut remaining_whole = whole_zec;
    while denom > 0 {
        while remaining_whole >= denom {
            outputs.push(
                denom
                    .checked_mul(ZATOSHIS_PER_ZEC)
                    .ok_or("Denomination zatoshi overflow")?,
            );
            remaining_whole -= denom;
        }
        denom /= 10;
    }

    let migratable_residual_threshold = migration_fee_zatoshi
        .checked_add(minimum_output_zatoshi)
        .ok_or("Residual fee threshold overflow")?;
    let orchard_change = if remainder > migratable_residual_threshold {
        outputs.push(remainder);
        None
    } else if remainder >= minimum_output_zatoshi {
        Some(remainder)
    } else {
        remainder = 0;
        None
    };

    if outputs.len() > MAX_DENOMINATION_OUTPUTS {
        return Err(format!(
            "Migration plan would create {} prepared notes, above the {} note limit",
            outputs.len(),
            MAX_DENOMINATION_OUTPUTS
        ));
    }

    let total_migratable_zatoshi = outputs.iter().try_fold(0u64, |acc, value| {
        acc.checked_add(*value)
            .ok_or("Migratable total overflow".to_string())
    })?;

    // When `remainder` is below minimum output it intentionally becomes extra
    // transaction fee. Keep the variable assignment explicit so tests can
    // lock the policy.
    let _dust_remainder_added_to_fee = remainder < minimum_output_zatoshi;

    Ok(DenominationPlan {
        migration_outputs: outputs,
        orchard_change,
        prep_fee_zatoshi,
        migration_fee_zatoshi,
        total_input_zatoshi,
        total_migratable_zatoshi,
    })
}

/// FFI representation of a [`DenominationPlan`].
///
/// `migration_outputs_ptr`/`migration_outputs_len` describe a heap-allocated
/// `u64` array, freed (along with this struct) by
/// [`zcashlc_free_denomination_plan`]. `has_orchard_change` indicates whether
/// `orchard_change` should be read.
#[repr(C)]
pub struct FfiDenominationPlan {
    migration_outputs_ptr: *mut u64,
    migration_outputs_len: usize,
    has_orchard_change: bool,
    orchard_change: u64,
    prep_fee_zatoshi: u64,
    migration_fee_zatoshi: u64,
    total_input_zatoshi: u64,
    total_migratable_zatoshi: u64,
}

/// Plans how to split a spendable Orchard balance into round-ZEC-denominated
/// outputs ahead of an Orchard -> Ironwood migration transfer. Pure
/// arithmetic - does not touch the wallet DB or build any transaction.
///
/// Returns a pointer to an [`FfiDenominationPlan`] on success, or null on
/// failure (e.g. the inputs would produce more than [`MAX_DENOMINATION_OUTPUTS`]
/// outputs). On failure the error can be retrieved via
/// `zcashlc_last_error_message`.
///
/// The returned pointer must be freed with [`zcashlc_free_denomination_plan`].
///
/// # Safety
///
/// - All zatoshi arguments must be non-negative.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_plan_orchard_denomination_split(
    total_input_zatoshi: i64,
    prep_fee_zatoshi: i64,
    migration_fee_zatoshi: i64,
    minimum_output_zatoshi: i64,
) -> *mut FfiDenominationPlan {
    let res = catch_panic(|| {
        let to_u64 = |label: &str, value: i64| -> anyhow::Result<u64> {
            u64::try_from(value).map_err(|_| anyhow::anyhow!("{label} must be non-negative"))
        };

        let plan = plan_denominations(
            to_u64("total_input_zatoshi", total_input_zatoshi)?,
            to_u64("prep_fee_zatoshi", prep_fee_zatoshi)?,
            to_u64("migration_fee_zatoshi", migration_fee_zatoshi)?,
            to_u64("minimum_output_zatoshi", minimum_output_zatoshi)?,
        )
        .map_err(|e| anyhow::anyhow!("Error planning denomination split: {e}"))?;

        let (migration_outputs_ptr, migration_outputs_len) =
            ptr_from_vec(plan.migration_outputs);

        Ok(Box::into_raw(Box::new(FfiDenominationPlan {
            migration_outputs_ptr,
            migration_outputs_len,
            has_orchard_change: plan.orchard_change.is_some(),
            orchard_change: plan.orchard_change.unwrap_or(0),
            prep_fee_zatoshi: plan.prep_fee_zatoshi,
            migration_fee_zatoshi: plan.migration_fee_zatoshi,
            total_input_zatoshi: plan.total_input_zatoshi,
            total_migratable_zatoshi: plan.total_migratable_zatoshi,
        })))
    });
    unwrap_exc_or_null(res)
}

/// Frees an [`FfiDenominationPlan`].
///
/// # Safety
///
/// - `ptr` must be non-null and must point to a struct having the layout of
///   [`FfiDenominationPlan`], as returned by
///   [`zcashlc_plan_orchard_denomination_split`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zcashlc_free_denomination_plan(ptr: *mut FfiDenominationPlan) {
    if !ptr.is_null() {
        let plan: Box<FfiDenominationPlan> = unsafe { Box::from_raw(ptr) };
        crate::free_ptr_from_vec(plan.migration_outputs_ptr, plan.migration_outputs_len);
        drop(plan);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMUM_OUTPUT_FOR_TEST: u64 = 1;

    #[test]
    fn planner_noops_when_prep_fee_consumes_balance() {
        let plan = plan_denominations(5_000, 10_000, 10_000, 1).unwrap();

        assert!(plan.migration_outputs.is_empty());
        assert_eq!(plan.total_migratable_zatoshi, 0);
        assert_eq!(plan.prep_fee_zatoshi, 5_000);
    }

    #[test]
    fn planner_creates_decimal_denominations_and_fee_positive_residual() {
        let plan = plan_denominations(1_234_500_000, 0, 10_000, MINIMUM_OUTPUT_FOR_TEST).unwrap();

        assert_eq!(
            plan.migration_outputs,
            vec![1_000_000_000, 100_000_000, 100_000_000, 34_500_000]
        );
        assert_eq!(plan.orchard_change, None);
        assert_eq!(plan.total_migratable_zatoshi, 1_234_500_000);
    }

    #[test]
    fn planner_keeps_non_fee_positive_residual_as_orchard_change() {
        let plan = plan_denominations(100_010_000, 0, 10_000, MINIMUM_OUTPUT_FOR_TEST).unwrap();

        assert_eq!(plan.migration_outputs, vec![100_000_000]);
        assert_eq!(plan.orchard_change, Some(10_000));
    }

    #[test]
    fn planner_reserves_prep_fee_before_decomposition() {
        let plan = plan_denominations(1_000_000_000, 10_000, 10_000, 1).unwrap();

        assert_eq!(
            plan.migration_outputs,
            vec![
                100_000_000,
                100_000_000,
                100_000_000,
                100_000_000,
                100_000_000,
                100_000_000,
                100_000_000,
                100_000_000,
                100_000_000,
                99_990_000,
            ]
        );
    }

    #[test]
    fn planner_rejects_more_than_max_prepared_outputs() {
        let err = plan_denominations(1_999_999_950_000_000, 0, 10_000, 1).unwrap_err();

        assert!(err.contains("above the 64 note limit"));
    }

    #[test]
    fn planner_dust_residual_below_minimum_output_is_folded_into_fee() {
        // Residual below minimum_output_zatoshi (here: 50_000) becomes extra fee,
        // not its own output and not Orchard change.
        let plan = plan_denominations(100_000_999, 0, 10_000, 50_000).unwrap();

        assert_eq!(plan.migration_outputs, vec![100_000_000]);
        assert_eq!(plan.orchard_change, None);
        assert_eq!(plan.total_migratable_zatoshi, 100_000_000);
    }
}
