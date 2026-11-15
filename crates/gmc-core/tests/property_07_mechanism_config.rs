//! Property 7 — 评判机制配置校验 (Validates: Requirements 3.3, 3.6).
//!
//! This is one of the numbered design correctness properties (Property 7). It asserts
//! the evaluation-mechanism config validation rule over a randomized input space:
//!
//! > *For any* evaluation-mechanism config, it is accepted **iff** it declares at least
//! > one acquisition mode **and** its consensus threshold lies in `(0, 1]`; otherwise it
//! > is rejected (`MechanismConfigInvalid`) and a previously-stored valid config is
//! > preserved.
//!
//! The acceptance side is exercised against
//! [`EvaluationMechanism::from_threshold_decimal`], which takes a raw [`Decimal`]
//! threshold and validates both the mode-count rule and the `(0, 1]` range up front.
//! The preserve-on-reject side is exercised against [`EvaluationMechanismSlot`]: a slot
//! seeded with a known-valid config must keep that config intact when an invalid
//! `try_set` is rejected.

use gmc_core::mechanism::{AcquisitionMode, EvaluationMechanism, EvaluationMechanismSlot};
use gmc_core::types::{Decimal, Ratio};
use proptest::prelude::*;
use proptest::sample::subsequence;

/// Raw scaling factor mirroring `Decimal::SCALE` (`10^6`); kept local because the scale
/// is an implementation detail of `Decimal`, while generators build raw values directly.
const SCALE: i128 = 1_000_000;

/// A possibly-empty set of distinct [`AcquisitionMode`]s.
///
/// Drawing a `0..=2` subsequence of the two modes covers every config shape that
/// matters for Requirement 3.3: the empty set (rejected), a single mode, and the
/// two-mode combination.
fn acquisition_mode_set() -> impl Strategy<Value = Vec<AcquisitionMode>> {
    subsequence(
        AcquisitionMode::ALL.to_vec(),
        0..=AcquisitionMode::ALL.len(),
    )
}

/// A consensus threshold drawn from `-0.5 ..= 1.5`, straddling both boundaries of the
/// valid `(0, 1]` interval so the generator exercises negative, zero, in-range, the
/// inclusive upper bound `1`, and `> 1` thresholds.
fn threshold_decimal() -> impl Strategy<Value = Decimal> {
    (-SCALE / 2..=SCALE + SCALE / 2).prop_map(Decimal::from_raw)
}

/// A fixed, known-valid baseline config used as the "previously-stored valid config"
/// for the preserve-on-reject checks.
fn valid_baseline() -> EvaluationMechanism {
    EvaluationMechanism::new(
        [AcquisitionMode::BountyTask],
        Ratio::new(Decimal::from_str("0.7").expect("valid decimal")).expect("valid ratio"),
        true,
    )
    .expect("baseline config is valid")
}

proptest! {
    // Run this numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(100))]

    // Feature: gmc-core-protocol, Property 7: 评判机制配置校验
    #[test]
    fn property_7_mechanism_config_validation(
        modes in acquisition_mode_set(),
        threshold in threshold_decimal(),
        exclude in any::<bool>(),
    ) {
        // Reference oracle (independent of the implementation): a config is valid iff it
        // declares at least one acquisition mode AND its threshold lies in (0, 1].
        let threshold_in_range = threshold > Decimal::ZERO && threshold <= Decimal::ONE;
        let expected_accept = !modes.is_empty() && threshold_in_range;

        let result =
            EvaluationMechanism::from_threshold_decimal(modes.iter().copied(), threshold, exclude);

        match result {
            Ok(mech) => {
                // Accepted: the oracle must agree it is a valid config.
                prop_assert!(
                    expected_accept,
                    "accepted an invalid config: modes={:?} threshold={}",
                    modes,
                    threshold
                );
                // ...and the accepted config must round-trip its inputs faithfully.
                prop_assert_eq!(mech.acquisition_mode_count(), modes.len());
                for m in &modes {
                    prop_assert!(mech.has_acquisition_mode(*m));
                }
                prop_assert_eq!(mech.consensus_threshold().value(), threshold);
                prop_assert_eq!(mech.exclude_high_intimacy(), exclude);
            }
            Err(e) => {
                // Rejected: the oracle must agree it is invalid, with the documented code.
                prop_assert!(
                    !expected_accept,
                    "rejected a valid config: modes={:?} threshold={}",
                    modes,
                    threshold
                );
                prop_assert_eq!(e, gmc_core::error::GmcError::MechanismConfigInvalid);
            }
        }

        // Preserve-on-reject (Requirement 3.6): a slot holding a known-valid config must
        // keep it unchanged whenever an invalid `try_set` is rejected. `try_set` takes a
        // `Ratio` (so a `> 1` threshold is unrepresentable); the two invalid shapes it can
        // express are "no acquisition mode" and "threshold == 0", both checked here.
        let baseline = valid_baseline();
        let mut slot = EvaluationMechanismSlot::with_config(baseline.clone());

        // Invalid update #1: no acquisition mode declared.
        let err = slot
            .try_set(std::iter::empty::<AcquisitionMode>(), Ratio::ONE, true)
            .expect_err("empty acquisition modes must be rejected");
        prop_assert_eq!(err, gmc_core::error::GmcError::MechanismConfigInvalid);
        prop_assert_eq!(slot.current(), Some(&baseline));

        // Invalid update #2: threshold == 0 (excluded by the open lower bound of (0, 1]).
        let err = slot
            .try_set([AcquisitionMode::ObjectiveMetering], Ratio::ZERO, true)
            .expect_err("zero threshold must be rejected");
        prop_assert_eq!(err, gmc_core::error::GmcError::MechanismConfigInvalid);
        prop_assert_eq!(slot.current(), Some(&baseline));
    }
}
